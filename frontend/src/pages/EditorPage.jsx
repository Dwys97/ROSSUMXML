import React, { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { Link } from 'react-router-dom';
import FileDropzone from '../components/common/FileDropzone';
import SchemaTree from '../components/editor/SchemaTree';
import MappingSVG from '../components/editor/MappingSVG';
import MappingsList from '../components/editor/MappingsList';
import { AISuggestionModal } from '../components/editor/AISuggestionModal';
import { AIBatchSuggestionModal } from '../components/editor/AIBatchSuggestionModal';
import { AILoadingToast } from '../components/editor/AILoadingToast';
import { UpgradePrompt } from '../components/editor/UpgradePrompt';
import Footer from '../components/common/Footer';
import TopNav from '../components/TopNav';
import { useAIFeatures, generateAISuggestion, generateBatchAISuggestions } from '../hooks/useAIFeatures';
import styles from './EditorPage.module.css';

// --- Helper Functions (moved outside the component for clarity) ---

// Regex to extract the value from a node name string, e.g., ': "some value"'
const valueRegex = /: "(.*?)"$/;
const getNodeValue = (nodeName) => {
    if (!nodeName) return '';
    const match = nodeName.match(valueRegex);
    return match ? match[1] : '';
};

// Function to find a node by its path in the tree data structure
const findNodeByPath = (tree, path) => {
    if (!tree || !path) return null;
    const pathParts = path.split(' > ');
    let currentNode = tree;

    // Check if the root node itself is the target
    if (pathParts.length === 1 && currentNode.path === path) {
        return currentNode;
    }

    for (const part of pathParts) {
        if (!currentNode || !currentNode.children) return null;
        // Find the child that matches the current part of the path
        const nextNode = currentNode.children.find(child => child.path.endsWith(part));
        if (!nextNode) return null;
        currentNode = nextNode;
    }
    return currentNode.path === path ? currentNode : null;
};


function EditorPage() {
    // --- STATE MANAGEMENT ---
    const [sourceTree, setSourceTree] = useState(null);
    const [targetTree, setTargetTree] = useState(null);
    const [mappings, setMappings] = useState([]);
    const [history, setHistory] = useState([]);
    const [selectedSourceCollection, setSelectedSourceCollection] = useState(null);
    const [selectedTargetCollection, setSelectedTargetCollection] = useState(null);
    const [isMappingFileLoaded, setIsMappingFileLoaded] = useState(false);
    const [sourceXmlContent, setSourceXmlContent] = useState(null);
    const [targetXmlContent, setTargetXmlContent] = useState(null);
    const [saveStatus, setSaveStatus] = useState(null);

    // --- AI FEATURE STATE ---
    const { hasAccess: hasAIAccess, loading: aiAccessLoading } = useAIFeatures();
    const [aiSuggestion, setAiSuggestion] = useState(null);
    const [aiLoading, setAiLoading] = useState(false);
    const [showUpgradePrompt, setShowUpgradePrompt] = useState(false);
    const [currentAITarget, setCurrentAITarget] = useState(null);
    
    // --- BATCH AI STATE ---
    const [batchSuggestions, setBatchSuggestions] = useState([]);
    const [showBatchModal, setShowBatchModal] = useState(false);
    const [batchLoading, setBatchLoading] = useState(false);
    const [isLoadingMore, setIsLoadingMore] = useState(false);
    const [remainingUnmappedCount, setRemainingUnmappedCount] = useState(0);
    const processingQueueRef = useRef([]);
    const mappingsRef = useRef(mappings);
    const shouldCancelBatchRef = useRef(false); // Flag to cancel background processing
    
    // Keep mappingsRef in sync with mappings
    useEffect(() => {
        mappingsRef.current = mappings;
    }, [mappings]);

    const nodeRefs = useRef(new Map());
    const editorSectionRef = useRef(null);
    const sourceTreeRef = useRef(null);
    const targetTreeRef = useRef(null);
    const mappingSVGRef = useRef(null);

    useEffect(() => {
        if (isMappingFileLoaded && mappingSVGRef.current) {
            const timer = setTimeout(() => {
                mappingSVGRef.current.updateLines();
                setIsMappingFileLoaded(false); // Reset the flag
            }, 100);

            return () => clearTimeout(timer);
        }
    }, [isMappingFileLoaded]);

    const registerNodeRef = useCallback((path, element) => {
        if (element) {
            nodeRefs.current.set(path, element);
        } else {
            nodeRefs.current.delete(path);
        }
    }, []);

    const updateMappings = useCallback((newMappings) => {
        setHistory(prevHistory => [...prevHistory, mappings]);
        setMappings(newMappings);
    }, [mappings]);

    const handleUndo = () => {
        if (history.length === 0) return;
        const previousMappings = history[history.length - 1];
        setMappings(previousMappings);
        setHistory(history.slice(0, -1));
    };

    // --- FILE HANDLERS ---
    const handleFile = async (content, setTree, isSource = null) => {
        if (!content) return;
        
        // Store the raw XML content
        if (isSource === true) {
            setSourceXmlContent(content);
        } else if (isSource === false) {
            setTargetXmlContent(content);
        }
        
        try {
            const response = await fetch('/api/schema/parse', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ xmlString: content }),
            });
            if (!response.ok) throw new Error(`Server responded with ${response.status}`);
            const data = await response.json();
            if (data.error) throw new Error(data.error);
            setTree(data.tree);
        } catch (error) {
            console.error('Error parsing XML:', error);
            alert(`Failed to parse XML: ${error.message}`);
        }
    };

    const handleMappingFile = (content) => {
        if (!content) return;
        try {
            const imported = JSON.parse(content);
            setHistory([]);
            
            // Reset collections first
            setSelectedSourceCollection(null);
            setSelectedTargetCollection(null);

            const staticMappings = imported.staticMappings || [];
            const allCollectionMappings = [];
            
            // Store collections temporarily (will use the last one for now, but can be extended)
            let lastSourceCollection = null;
            let lastTargetCollection = null;
            
            // Process each collection mapping
            (imported.collectionMappings || []).forEach(cm => {
                // Track collection info
                if (cm.sourceItemElementName) {
                    const srcName = cm.sourceItemElementName.split('[')[0];
                    lastSourceCollection = {
                        path: `${cm.sourceCollectionPath} > ${srcName}[0]`,
                        name: cm.sourceItemElementName,
                        parentPath: cm.sourceCollectionPath,
                    };
                }
                if (cm.targetItemElementName) {
                    const tgtName = cm.targetItemElementName.split('[')[0];
                    lastTargetCollection = {
                        path: `${cm.targetCollectionPath} > ${tgtName}[0]`,
                        name: cm.targetItemElementName,
                        parentPath: cm.targetCollectionPath
                    };
                }

                // Process mappings within this collection
                const mappingsInCollection = (cm.mappings || [])
                    .filter(m => m.type !== 'generated_line_number') // Skip auto-generated entries
                    .map(m => {
                        const sourceItemName = (cm.sourceItemElementName || '').split('[')[0];
                        const targetItemName = (cm.targetItemElementName || '').split('[')[0];
                        return {
                            source: m.source ? `${cm.sourceCollectionPath} > ${sourceItemName}[0] > ${m.source}` : undefined,
                            target: m.target ? `${cm.targetCollectionPath} > ${targetItemName}[0] > ${m.target}` : undefined,
                            type: m.type || 'element',
                            value: m.value
                        };
                    })
                    .filter(m => m.target); // Ensure mappings have a target
                
                allCollectionMappings.push(...mappingsInCollection);
            });
            
            // Set collections (currently uses the last one, but this allows for future multi-collection support)
            if (lastSourceCollection) {
                setSelectedSourceCollection(lastSourceCollection);
            }
            if (lastTargetCollection) {
                setSelectedTargetCollection(lastTargetCollection);
            }
            
            // Combine static and collection mappings
            setMappings([...staticMappings, ...allCollectionMappings]);
            setIsMappingFileLoaded(true);
        } catch (error) {
            console.error('Invalid mapping JSON:', error);
            alert(`Failed to parse mapping file: ${error.message}`);
        }
    };

    // --- INTERACTION HANDLERS ---
    const handleDrop = (sourcePath, targetPath) => {
        const newMapping = { source: sourcePath, target: targetPath, type: 'element' };
        const existingIndex = mappings.findIndex(m => m.target === targetPath);
        
        let newMappings = [...mappings];
        if (existingIndex !== -1) {
            if (window.confirm('This target is already mapped. Do you want to replace it?')) {
                newMappings[existingIndex] = newMapping;
                updateMappings(newMappings);
            }
        } else {
            newMappings.push(newMapping);
            updateMappings(newMappings);
        }
    };

    const handleCustomValue = (targetPath) => {
        const existing = mappings.find(m => m.target === targetPath);
        const value = window.prompt('Enter custom value:', existing?.value || '');
        if (value !== null) {
            const newMapping = { type: 'custom_element', value, target: targetPath };
            const newMappings = mappings.filter(m => m.target !== targetPath);
            updateMappings([...newMappings, newMapping]);
        }
    };
    
    const handleCollectionSelect = (node, isChecked, isSource) => {
        const collection = isChecked ? {
            path: node.path,
            name: node.pathName,
            parentPath: node.path.split(' > ').slice(0, -1).join(' > ')
        } : null;

        if (isSource) {
            setSelectedSourceCollection(collection);
        } else {
            setSelectedTargetCollection(collection);
        }
    };

    // --- AI SUGGESTION HANDLERS ---
    const getAllSourceNodes = useCallback((tree) => {
        if (!tree) return [];
        const nodes = [];
        
        const traverse = (node) => {
            // Check for leaf nodes (no children) regardless of type
            if (!node.children || node.children.length === 0) {
                nodes.push({
                    name: node.name,
                    path: node.path,
                    type: node.type || 'element'
                });
            }
            
            if (node.children) {
                node.children.forEach(child => traverse(child));
            }
        };
        
        traverse(tree);
        return nodes;
    }, []);

    const handleAISuggest = useCallback(async (targetNode) => {
        // Check if user has AI access
        if (!hasAIAccess) {
            setShowUpgradePrompt(true);
            return;
        }

        // Check if both trees are loaded
        if (!sourceTree || !targetTree) {
            alert('Please upload both Source and Target XML files first.');
            return;
        }

        setCurrentAITarget(targetNode);
        setAiLoading(true);

        try {
            // Get all source nodes as potential mapping candidates
            const sourceNodes = getAllSourceNodes(sourceTree);
            
            if (sourceNodes.length === 0) {
                alert('No source elements found to map from.');
                setAiLoading(false);
                return;
            }

            // Prepare enhanced context for AI with UK customs domain
            const context = {
                sourceSchema: sourceTree.name || 'UK Customs Export/Import Data',
                targetSchema: targetTree.name || 'UK Customs Software System',
                existingMappings: mappings.map(m => ({
                    source: m.source,
                    target: m.target
                })),
                domain: 'UK Customs and International Trade'
            };

            // Call AI service - Note: We're finding best SOURCE for a given TARGET
            // So we pass ALL source nodes and the single target node
            const result = await generateAISuggestion(
                targetNode,
                sourceNodes,
                context
            );

            setAiSuggestion(result.suggestion);
        } catch (error) {
            console.error('AI suggestion error:', error);
            alert(error.message || 'Failed to generate AI suggestion. Please try again.');
        } finally {
            setAiLoading(false);
        }
    }, [hasAIAccess, sourceTree, targetTree, mappings, getAllSourceNodes]);

    const handleAcceptAISuggestion = useCallback(() => {
        if (!aiSuggestion || !currentAITarget) return;

        // Create mapping just like manual drag-and-drop
        const newMapping = {
            source: aiSuggestion.sourceElement?.path || aiSuggestion.sourceElement,
            target: currentAITarget.path || currentAITarget,
            type: 'element'
        };

        const existingIndex = mappings.findIndex(m => m.target === newMapping.target);
        let newMappings = [...mappings];

        if (existingIndex !== -1) {
            // Replace existing mapping
            newMappings[existingIndex] = newMapping;
        } else {
            // Add new mapping
            newMappings.push(newMapping);
        }

        updateMappings(newMappings);
        
        // Close modal and reset
        setAiSuggestion(null);
        setCurrentAITarget(null);

        // Trigger SVG line update
        setTimeout(() => {
            if (mappingSVGRef.current) {
                mappingSVGRef.current.updateLines();
            }
        }, 100);
    }, [aiSuggestion, currentAITarget, mappings, updateMappings]);

    const handleRejectAISuggestion = useCallback(() => {
        setAiSuggestion(null);
        setCurrentAITarget(null);
    }, []);

    const handleRegenerateAISuggestion = useCallback(async () => {
        if (!currentAITarget) return;
        
        // Close current suggestion and regenerate
        setAiSuggestion(null);
        await handleAISuggest(currentAITarget);
    }, [currentAITarget, handleAISuggest]);

    // --- BATCH AI SUGGESTION HANDLERS ---
    
    // Progressive batch processing function
    const processNextBatch = useCallback(async (remainingSources, targetLeaves) => {
        const BATCH_SIZE = 5;
        let currentIndex = 0;
        
        while (currentIndex < remainingSources.length) {
            // Check if processing should be cancelled (modal closed)
            if (shouldCancelBatchRef.current) {
                console.log('Background batch processing cancelled by user');
                setIsLoadingMore(false);
                setRemainingUnmappedCount(0);
                return;
            }
            
            // Wait a bit before next batch to not overwhelm the server
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Check again after delay in case modal was closed during wait
            if (shouldCancelBatchRef.current) {
                console.log('Background batch processing cancelled by user');
                setIsLoadingMore(false);
                setRemainingUnmappedCount(0);
                return;
            }
            
            const batch = remainingSources.slice(currentIndex, currentIndex + BATCH_SIZE);
            const remainingAfterThisBatch = remainingSources.length - (currentIndex + BATCH_SIZE);
            currentIndex += BATCH_SIZE;
            
            try {
                // Get FRESH context with current mappings (including accepted suggestions)
                // Use mappingsRef.current to get the latest mappings without recreating this callback
                const freshContext = {
                    sourceSchema: sourceTree?.name || 'UK Customs Export/Import Data',
                    targetSchema: targetTree?.name || 'UK Customs Software System', 
                    existingMappings: mappingsRef.current.map(m => ({ source: m.source, target: m.target })),
                    domain: 'UK Customs and International Trade'
                };
                
                const mappingRequests = batch.map(sourceNode => ({
                    sourceNode: sourceNode,
                    targetNodes: targetLeaves.slice(0, 50),
                    context: freshContext
                }));
                
                const result = await generateBatchAISuggestions(mappingRequests);
                
                // Append new suggestions to existing ones
                setBatchSuggestions(prev => [...prev, ...(result.suggestions || [])]);
                
                // Update remaining count with elements still in queue
                setRemainingUnmappedCount(Math.max(0, remainingAfterThisBatch));
                
                // Hide loading if this was the last batch
                if (remainingAfterThisBatch <= 0) {
                    setIsLoadingMore(false);
                }
                
            } catch (error) {
                console.error('Error processing batch:', error);
                // Continue with next batch even if one fails
            }
        }
        
        // Ensure loading indicator is off when done
        setIsLoadingMore(false);
    }, [sourceTree, targetTree]);
    
    const handleBatchAISuggest = useCallback(async () => {
        if (!sourceTree || !targetTree || !hasAIAccess) {
            setShowUpgradePrompt(true);
            return;
        }

        // Reset cancellation flag when starting new batch
        shouldCancelBatchRef.current = false;
        
        setBatchLoading(true);
        // Don't show modal yet - wait until first batch is ready
        setBatchSuggestions([]); // Clear previous suggestions
        
        try {
            // Get all leaf nodes directly using existing helper functions
            const allSourceLeaves = getAllSourceNodes(sourceTree);
            const allTargetLeaves = getAllSourceNodes(targetTree);
            
            // Filter out already mapped elements BY PATH (not by name)
            const mappedSources = new Set(mappings.map(m => m.source));
            const mappedTargets = new Set(mappings.map(m => m.target));
            
            const unmappedSourceLeaves = allSourceLeaves.filter(el => !mappedSources.has(el.path));
            const unmappedTargetLeaves = allTargetLeaves.filter(el => !mappedTargets.has(el.path));
            
            const totalUnmapped = unmappedSourceLeaves.length;
            
            if (totalUnmapped === 0) {
                alert('No unmapped elements found. All elements are already mapped!');
                setShowBatchModal(false);
                setBatchLoading(false);
                return;
            }
            
            // PROGRESSIVE LOADING: Process in batches of 5
            const BATCH_SIZE = 5;
            const firstBatch = unmappedSourceLeaves.slice(0, BATCH_SIZE);
            const remainingBatches = unmappedSourceLeaves.slice(BATCH_SIZE);
            
            // Store remaining batches for progressive loading
            processingQueueRef.current = remainingBatches;
            
            // Set remaining count to elements NOT in first batch (i.e., in queue)
            setRemainingUnmappedCount(remainingBatches.length);
            
            // Prepare enhanced context with UK customs domain information
            const optimizedContext = {
                sourceSchema: sourceTree?.name || 'UK Customs Export/Import Data',
                targetSchema: targetTree?.name || 'UK Customs Software System', 
                existingMappings: mappings.map(m => ({ source: m.source, target: m.target })),
                domain: 'UK Customs and International Trade',
                standards: ['CDS', 'CHIEF', 'HMRC', 'EDIFACT']
            };
            
            // Generate FIRST BATCH immediately
            const firstMappingRequests = firstBatch.map(sourceNode => ({
                sourceNode: sourceNode,
                targetNodes: unmappedTargetLeaves.slice(0, 50),
                context: optimizedContext
            }));
            
            const firstResult = await generateBatchAISuggestions(firstMappingRequests);
            setBatchSuggestions(firstResult.suggestions || []);
            setBatchLoading(false);
            
            // NOW show modal with first batch ready
            setShowBatchModal(true);
            
            // Start processing REMAINING BATCHES in background (only if there are any)
            if (remainingBatches.length > 0) {
                // Set isLoadingMore BEFORE starting background processing
                setIsLoadingMore(true);
                processNextBatch(remainingBatches, unmappedTargetLeaves);
            } else {
                // No more batches, ensure loading is off
                setIsLoadingMore(false);
                setRemainingUnmappedCount(0);
            }
            
        } catch (error) {
            console.error('Batch AI suggestion error:', error);
            alert(error.message || 'Failed to generate AI suggestions. Please try again.');
            // Ensure loading states are reset on error
            setShowBatchModal(false);
            setBatchLoading(false);
            setIsLoadingMore(false);
            setRemainingUnmappedCount(0);
        }
    }, [sourceTree, targetTree, mappings, hasAIAccess, getAllSourceNodes, processNextBatch]);

    const handleAcceptBatchSuggestions = useCallback((selectedSuggestions) => {
        if (!selectedSuggestions.length) return;

        const newMappings = selectedSuggestions.map(suggestion => ({
            id: Date.now() + Math.random(),
            source: suggestion.sourceElement?.path || suggestion.sourceElement,
            target: suggestion.targetElement?.path || suggestion.targetElement,
            sourceValue: getNodeValue(
                findNodeByPath(sourceTree, suggestion.sourceElement?.path || suggestion.sourceElement)?.name || ''
            ),
            targetValue: getNodeValue(
                findNodeByPath(targetTree, suggestion.targetElement?.path || suggestion.targetElement)?.name || ''
            )
        }));

        updateMappings([...mappings, ...newMappings]);
        // Don't close modal or clear suggestions - let user continue
    }, [mappings, sourceTree, targetTree, updateMappings]);

    const handleCloseBatchModal = useCallback(() => {
        // Signal background processing to stop
        shouldCancelBatchRef.current = true;
        
        setShowBatchModal(false);
        setBatchSuggestions([]);
        setIsLoadingMore(false);
        setRemainingUnmappedCount(0);
    }, []);

    const handleRegenerateBatchSuggestions = useCallback(async () => {
        await handleBatchAISuggest();
    }, [handleBatchAISuggest]);

    const handleRegenerateOneSuggestion = useCallback(async (suggestion, index) => {
        // Regenerate AI suggestion for this specific source node
        try {
            const sourceNode = suggestion.sourceElement;
            const allTargetLeaves = getAllSourceNodes(targetTree);
            
            // Filter out already mapped targets
            const mappedTargets = new Set(mappings.map(m => m.target));
            const unmappedTargetLeaves = allTargetLeaves.filter(el => !mappedTargets.has(el.path));
            
            const optimizedContext = {
                sourceSchema: sourceTree?.name || 'UK Customs Export/Import Data',
                targetSchema: targetTree?.name || 'UK Customs Software System', 
                existingMappings: mappings.map(m => ({ source: m.source, target: m.target })),
                domain: 'UK Customs and International Trade'
            };
            
            const mappingRequest = {
                sourceNode: sourceNode,
                targetNodes: unmappedTargetLeaves.slice(0, 50),
                context: optimizedContext
            };
            
            const result = await generateBatchAISuggestions([mappingRequest]);
            
            // Replace the suggestion at this index
            if (result.suggestions && result.suggestions.length > 0) {
                const newSuggestions = [...batchSuggestions];
                newSuggestions[index] = result.suggestions[0];
                setBatchSuggestions(newSuggestions);
            }
        } catch (error) {
            console.error('Failed to regenerate suggestion:', error);
            alert('Failed to regenerate suggestion. Please try again.');
        }
    }, [sourceTree, targetTree, mappings, batchSuggestions, getAllSourceNodes]);

    // --- SAVE LOGIC ---
    const handleSaveMappings = () => {
        const staticMappings = [];
        const collectionMappings = [];

        if (selectedSourceCollection && selectedTargetCollection) {
            const itemCollectionMappings = [];
            mappings.forEach(m => {
                // Custom elements or elements without a source should go to static mappings
                if (m.type === 'custom_element' || !m.source) {
                    staticMappings.push(m);
                    return;
                }
                
                const isSourceIn = m.source && m.source.startsWith(selectedSourceCollection.path);
                const isTargetIn = m.target.startsWith(selectedTargetCollection.path);
                
                if (isSourceIn && isTargetIn) {
                    itemCollectionMappings.push(m);
                } else {
                    staticMappings.push(m);
                }
            });

            const relativeMappings = itemCollectionMappings.map(m => ({
                source: m.source ? m.source.substring(selectedSourceCollection.path.length + 3) : undefined, // +3 for ' > '
                target: m.target.substring(selectedTargetCollection.path.length + 3), // +3 for ' > '
                type: m.type,
                value: m.value
            }));

            // Add line number generation if there are relative mappings
            if (relativeMappings.length > 0) {
                relativeMappings.push({
                    type: "generated_line_number",
                    target: "LineNo[0]" // Target the LineNo element within each item
                });
            }

            collectionMappings.push({
                sourceCollectionPath: selectedSourceCollection.parentPath,
                targetCollectionPath: selectedTargetCollection.parentPath,
                sourceItemElementName: selectedSourceCollection.name,
                targetItemElementName: selectedTargetCollection.name,
                mappings: relativeMappings,
            });
        } else {
            mappings.forEach(m => staticMappings.push(m));
        }

        const dataToSave = {
            rootElement: targetTree ? targetTree.pathName : "root",
            staticMappings,
            collectionMappings,
        };

        const blob = new Blob([JSON.stringify(dataToSave, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'mappings.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    };

    const handleSaveToApiSettings = async () => {
        // Check if we have both target XML and mappings
        if (!targetXmlContent) {
            alert('Please upload a target XML schema first.');
            return;
        }
        
        if (mappings.length === 0) {
            alert('Please create at least one mapping before saving.');
            return;
        }

        // Prepare the mapping JSON (same as download)
        const staticMappings = [];
        const collectionMappings = [];

        if (selectedSourceCollection && selectedTargetCollection) {
            const relativeMappings = mappings.map(m => ({
                source: m.source ? m.source.substring(selectedSourceCollection.path.length + 3) : undefined,
                target: m.target.substring(selectedTargetCollection.path.length + 3),
                type: m.type,
                value: m.value
            }));

            if (relativeMappings.length > 0) {
                relativeMappings.push({
                    type: "generated_line_number",
                    target: "LineNo[0]"
                });
            }

            collectionMappings.push({
                sourceCollectionPath: selectedSourceCollection.parentPath,
                targetCollectionPath: selectedTargetCollection.parentPath,
                sourceItemElementName: selectedSourceCollection.name,
                targetItemElementName: selectedTargetCollection.name,
                mappings: relativeMappings,
            });
        } else {
            mappings.forEach(m => staticMappings.push(m));
        }

        const mappingJson = {
            rootElement: targetTree ? targetTree.pathName : "root",
            staticMappings,
            collectionMappings,
        };

        // Prompt for mapping name
        const mappingName = prompt('Enter a name for this mapping configuration:');
        if (!mappingName || mappingName.trim() === '') {
            return;
        }

        const description = prompt('Enter a description (optional):') || '';

        setSaveStatus('Saving...');

        try {
            const token = localStorage.getItem('token');
            const response = await fetch('/api/api-settings/mappings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    mapping_name: mappingName.trim(),
                    description: description.trim(),
                    mapping_json: mappingJson,
                    destination_schema_xml: targetXmlContent,
                    is_default: false
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to save mapping');
            }

            setSaveStatus('Saved!');
            alert(`Mapping "${mappingName}" has been saved to API Settings!`);
            
            // Clear status after 3 seconds
            setTimeout(() => setSaveStatus(null), 3000);
        } catch (error) {
            console.error('Error saving mapping:', error);
            setSaveStatus(null);
            alert(`Failed to save mapping: ${error.message}`);
        }
    };

    const mappedSourcePaths = useMemo(() => new Set(mappings.filter(m => m.source).map(m => m.source)), [mappings]);
    const mappedTargetPaths = useMemo(() => new Set(mappings.map(m => m.target)), [mappings]);

    const targetValueMap = useMemo(() => {
        const valueMap = new Map();
        if (!sourceTree) return valueMap;

        mappings.forEach(m => {
            if (m.type === 'custom_element') {
                valueMap.set(m.target, { type: 'custom', value: m.value });
            } else if (m.source) {
                const sourceNode = findNodeByPath(sourceTree, m.source);
                if (sourceNode) {
                    valueMap.set(m.target, { type: 'mapped', value: getNodeValue(sourceNode.name) });
                }
            }
        });
        return valueMap;
    }, [mappings, sourceTree]);

    return (
        <>
            <TopNav />
            <div className="app-container extra-spacing" style={{ paddingTop: '100px' }}>
                <Link to="/transformer" className="home-link" style={{ marginTop: '0' }}>← Back to Transformer</Link>

                <div className="upload-section">
                <FileDropzone onFileSelect={(files) => handleFile(files[0]?.content, setSourceTree, true)}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M12 18V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M9 15L12 12L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Source XML</h3>
                    <p>Upload your source XML schema</p>
                </FileDropzone>
                <FileDropzone onFileSelect={(files) => handleFile(files[0]?.content, setTargetTree, false)}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 13H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 17H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M10 9H9H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Target XML</h3>
                    <p>Upload your target XML schema</p>
                </FileDropzone>
                <FileDropzone onFileSelect={(files) => handleMappingFile(files[0]?.content)}>
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <circle cx="12" cy="13" r="2" stroke="currentColor" strokeWidth="2"/>
                            <path d="M12 11V9" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <path d="M12 17V15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <path d="M14.5 13.5L16 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                            <path d="M8 11L9.5 12.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                        </svg>
                    </div>
                    <h3>Mapping JSON</h3>
                    <p>Load existing mapping configuration</p>
                </FileDropzone>
            </div>

            <div className={styles.editorSection} ref={editorSectionRef}>
                <SchemaTree
                    ref={sourceTreeRef}
                    title="Source Schema"
                    treeData={sourceTree}
                    isSource={true}
                    mappedPaths={mappedSourcePaths}
                    selectedCollection={selectedSourceCollection}
                    onCollectionSelect={handleCollectionSelect}
                    registerNodeRef={registerNodeRef}
                />

                <div className="mapping-svg-container">
                <MappingSVG
                    ref={mappingSVGRef}
                    mappings={mappings}
                    nodeRefs={nodeRefs}
                    editorRef={editorSectionRef}
                    sourceTreeRef={sourceTreeRef}
                    targetTreeRef={targetTreeRef}
                />
                </div>

                <SchemaTree
                    ref={targetTreeRef}
                    title="Target Schema"
                    treeData={targetTree}
                    isSource={false}
                    mappedPaths={mappedTargetPaths}
                    selectedCollection={selectedTargetCollection}
                    onDrop={handleDrop}
                    onCustomValue={handleCustomValue}
                    onCollectionSelect={handleCollectionSelect}
                    registerNodeRef={registerNodeRef}
                    targetValueMap={targetValueMap}
                    hasAIAccess={hasAIAccess}
                    onAISuggest={handleAISuggest}
                    aiLoading={aiLoading}
                />

                <MappingsList
                    mappings={mappings}
                    onUpdateMappings={updateMappings}
                    onSave={handleSaveMappings}
                    onSaveToApi={handleSaveToApiSettings}
                    onUndo={handleUndo}
                    canUndo={history.length > 0}
                    saveStatus={saveStatus}
                    hasAIAccess={hasAIAccess}
                    onAISuggestAll={handleBatchAISuggest}
                    aiLoading={batchLoading}
                />
            </div>
            
            <section className="how-to-use">
                <h2>How to Use</h2>
                <div className="steps-container">
                    <div className="step">
                        <div className="step-number">1</div>
                        <div className="step-text">
                            <h3>Upload Schemas</h3>
                            <p>Upload your source and target XML schema files to begin mapping.</p>
                        </div>
                    </div>
                    <div className="step">
                        <div className="step-number">2</div>
                        <div className="step-text">
                            <h3>Create Mappings</h3>
                            <p>Drag elements from the source schema and drop them onto target elements.</p>
                        </div>
                    </div>
                    <div className="step">
                        <div className="step-number">3</div>
                        <div className="step-text">
                            <h3>Export Configuration</h3>
                            <p>Download your mapping configuration as JSON for use in data transformation.</p>
                        </div>
                    </div>
                </div>
            </section>
            </div>
            <Footer text="Created by Daniils Radionovs" />

            {/* AI Loading Toast - Shown while initial batch is being generated */}
            {batchLoading && !showBatchModal && (
                <AILoadingToast
                    message="Generating AI suggestions..."
                    subtitle="Analyzing schemas and creating intelligent mappings"
                />
            )}

            {/* AI Suggestion Modal */}
            {aiSuggestion && (
                <AISuggestionModal
                    suggestion={aiSuggestion}
                    onAccept={handleAcceptAISuggestion}
                    onReject={handleRejectAISuggestion}
                    onRegenerate={handleRegenerateAISuggestion}
                    onClose={handleRejectAISuggestion}
                    loading={aiLoading}
                />
            )}

            {/* AI Batch Suggestion Modal */}
            {showBatchModal && (
                <AIBatchSuggestionModal
                    suggestions={batchSuggestions}
                    onAcceptSuggestion={handleAcceptBatchSuggestions}
                    onAcceptAll={handleAcceptBatchSuggestions}
                    onRegenerateAll={handleRegenerateBatchSuggestions}
                    onRegenerateOne={handleRegenerateOneSuggestion}
                    onClose={handleCloseBatchModal}
                    loading={batchLoading}
                    isLoadingMore={isLoadingMore}
                    remainingCount={remainingUnmappedCount}
                />
            )}

            {/* Upgrade Prompt for Free Tier Users */}
            {showUpgradePrompt && (
                <UpgradePrompt onClose={() => setShowUpgradePrompt(false)} />
            )}
        </>
    );
}

export default EditorPage;