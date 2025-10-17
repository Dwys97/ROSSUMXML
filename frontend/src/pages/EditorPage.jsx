import React, { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { Link } from 'react-router-dom';
import FileDropzone from '../components/common/FileDropzone';
import SchemaTree from '../components/editor/SchemaTree';
import MappingSVG from '../components/editor/MappingSVG';
import MappingsList from '../components/editor/MappingsList';
import { AISuggestionModal } from '../components/editor/AISuggestionModal';
import { AIBatchSuggestionModal } from '../components/editor/AIBatchSuggestionModal';
import { UpgradePrompt } from '../components/editor/UpgradePrompt';
import { LoadingSpinner } from '../components/editor/LoadingSpinner';
import Footer from '../components/common/Footer';
import TopNav from '../components/TopNav';
import { useAIFeatures, generateAISuggestion, generateBatchAISuggestions } from '../hooks/useAIFeatures';
import { useDataPreload } from '../contexts/DataPreloadContext';
import { parseXMLToTree } from '../utils/xmlParser';
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
    // --- DATA PRELOAD CONTEXT ---
    const { mappings: preloadedMappings } = useDataPreload();
    
    // --- STATE MANAGEMENT ---
    const [sourceTree, setSourceTree] = useState(null);
    const [targetTree, setTargetTree] = useState(null);
    const [mappings, setMappings] = useState([]);
    const [history, setHistory] = useState([]);
    const [selectedSourceCollection, setSelectedSourceCollection] = useState(null);
    const [selectedTargetCollection, setSelectedTargetCollection] = useState(null);
    const [isMappingFileLoaded, setIsMappingFileLoaded] = useState(false);
    const [sourceXmlContent, setSourceXmlContent] = useState(null); // Stores raw source XML for future schema validation/API submission
    const [targetXmlContent, setTargetXmlContent] = useState(null); // Stores raw target XML, used in handleSaveToApiSettings
    const [saveStatus, setSaveStatus] = useState(null);

    // --- SAVED MAPPINGS STATE (from API Settings) ---
    const [savedMappings, setSavedMappings] = useState([]);
    const [selectedSavedSchema, setSelectedSavedSchema] = useState('');
    const [selectedSavedMappingJson, setSelectedSavedMappingJson] = useState('');

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
    const [loadingMessage, setLoadingMessage] = useState('');
    const [loadingSubMessage, setLoadingSubMessage] = useState('');
    const [loadingProgress, setLoadingProgress] = useState(null);
    const [isLoadingMore, setIsLoadingMore] = useState(false);
    const [remainingUnmappedCount, setRemainingUnmappedCount] = useState(0);

    const nodeRefs = useRef(new Map());
    const editorSectionRef = useRef(null);
    const sourceTreeRef = useRef(null);
    const loadingAbortRef = useRef(false); // Flag to abort background loading
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

    // Use preloaded mappings from context instead of fetching
    useEffect(() => {
        if (preloadedMappings && preloadedMappings.length >= 0) {
            console.log('✅ [Editor] Using preloaded mappings:', preloadedMappings.length, 'items');
            if (preloadedMappings.length > 0) {
                console.log('📋 [Editor] First mapping sample:', {
                    id: preloadedMappings[0].id,
                    name: preloadedMappings[0].mapping_name,
                    has_schema: !!preloadedMappings[0].destination_schema_xml,
                    has_mapping: !!preloadedMappings[0].mapping_json
                });
            }
            setSavedMappings(preloadedMappings);
        }
    }, [preloadedMappings]);

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
    const handleFile = useCallback((content, setTree, isSource = null) => {
        if (!content) return;
        
        // Store the raw XML content
        if (isSource === true) {
            setSourceXmlContent(content);
        } else if (isSource === false) {
            setTargetXmlContent(content);
        }
        
        try {
            // Parse XML client-side for instant tree rendering
            const tree = parseXMLToTree(content);
            setTree(tree);
        } catch (error) {
            console.error('Error parsing XML:', error);
            alert(`Failed to parse XML: ${error.message}`);
        }
    }, []);

    // Handler to load ONLY destination schema from saved mappings
    const handleSavedSchemaSelect = async (e) => {
        const mappingId = e.target.value;
        console.log('🔍 [Schema Select] Mapping ID selected:', mappingId);
        setSelectedSavedSchema(mappingId);
        
        if (!mappingId) {
            console.log('⚠️  [Schema Select] No mapping ID, clearing selection');
            return;
        }
        
        // 🛑 VALIDATION: Prevent loading destination before source
        if (!sourceTree) {
            alert('⚠️ Please upload or select a Source XML file first before loading the destination schema.');
            setSelectedSavedSchema(''); // Reset the selector
            e.target.value = ''; // Reset dropdown UI
            return;
        }
        
        try {
            // Fetch the full mapping details from the API (includes destination_schema_xml and mapping_json)
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            if (!token) {
                console.error('❌ [Schema Select] No auth token found');
                return;
            }
            
            console.log(`🔍 [Schema Select] Fetching full mapping details for ID: ${mappingId}...`);
            const response = await fetch(`/api/api-settings/mappings/${mappingId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Failed to fetch mapping: ${response.status} ${response.statusText}`);
            }
            
            const fullMapping = await response.json();
            console.log('✅ [Schema Select] Full mapping loaded:', fullMapping.mapping_name);
            console.log('📄 [Schema Select] Has destination_schema_xml:', !!fullMapping.destination_schema_xml);
            console.log('📏 [Schema Select] Schema XML length:', fullMapping.destination_schema_xml?.length || 0);
            
            if (fullMapping.destination_schema_xml) {
                console.log('🚀 [Schema Select] Calling handleFile with schema XML...');
                await handleFile(fullMapping.destination_schema_xml, setTargetTree, false);
                setTargetXmlContent(fullMapping.destination_schema_xml);
                console.log('✅ [Schema Select] Successfully loaded destination schema from:', fullMapping.mapping_name);
            } else {
                console.warn('⚠️  [Schema Select] No destination_schema_xml in mapping');
                alert('This mapping does not have a destination schema saved.');
            }
        } catch (error) {
            console.error('❌ [Schema Select] Error loading saved schema:', error);
            alert('Failed to load saved schema. Please check the console for details.');
        }
    };

    // Handler to load ONLY mapping JSON from saved mappings
    const handleSavedMappingJsonSelect = async (e) => {
        const mappingId = e.target.value;
        console.log('🔍 [Mapping Select] Mapping ID selected:', mappingId);
        setSelectedSavedMappingJson(mappingId);
        
        if (!mappingId) {
            console.log('⚠️  [Mapping Select] No mapping ID, clearing selection');
            return;
        }
        
        // 🛑 VALIDATION: Prevent loading mapping before source
        if (!sourceTree) {
            alert('⚠️ Please upload or select a Source XML file first before loading the mapping.');
            setSelectedSavedMappingJson(''); // Reset the selector
            e.target.value = ''; // Reset dropdown UI
            return;
        }
        
        // 🛑 VALIDATION: Prevent loading mapping before destination
        if (!targetTree) {
            alert('⚠️ Please upload or select a Destination XML file first before loading the mapping.');
            setSelectedSavedMappingJson(''); // Reset the selector
            e.target.value = ''; // Reset dropdown UI
            return;
        }
        
        try {
            // Fetch the full mapping details from the API (includes destination_schema_xml and mapping_json)
            const token = localStorage.getItem('token') || sessionStorage.getItem('token');
            if (!token) {
                console.error('❌ [Mapping Select] No auth token found');
                return;
            }
            
            console.log(`🔍 [Mapping Select] Fetching full mapping details for ID: ${mappingId}...`);
            const response = await fetch(`/api/api-settings/mappings/${mappingId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Failed to fetch mapping: ${response.status} ${response.statusText}`);
            }
            
            const fullMapping = await response.json();
            console.log('✅ [Mapping Select] Full mapping loaded:', fullMapping.mapping_name);
            console.log('📄 [Mapping Select] Has mapping_json:', !!fullMapping.mapping_json);
            console.log('📏 [Mapping Select] Mapping JSON length:', fullMapping.mapping_json?.length || 0);
            
            if (fullMapping.mapping_json) {
                console.log('🔍 [Mapping Select] Parsing mapping JSON...');
                const mappingData = JSON.parse(fullMapping.mapping_json);
                console.log('✅ [Mapping Select] Parsed mapping data:', Object.keys(mappingData).length, 'entries');
                
                // Handle different mapping formats (saved vs exported)
                let convertedMappings = [];
                
                // Check if this is a structured format with staticMappings/collectionMappings
                if (mappingData.staticMappings || mappingData.collectionMappings) {
                    console.log('📋 [Mapping Select] Detected structured mapping format');
                    
                    // Process static mappings
                    const staticMappings = (mappingData.staticMappings || []).map(m => ({
                        id: Date.now() + Math.random(),
                        source: m.source,
                        target: m.target,
                        type: m.type || 'element',
                        value: m.value,
                        transformation: m.transformation || 'direct'
                    }));
                    
                    // Process collection mappings
                    const collectionMappings = [];
                    (mappingData.collectionMappings || []).forEach(cm => {
                        const mappingsInCollection = (cm.mappings || [])
                            .filter(m => m.type !== 'generated_line_number')
                            .map(m => {
                                const sourceItemName = (cm.sourceItemElementName || '').split('[')[0];
                                const targetItemName = (cm.targetItemElementName || '').split('[')[0];
                                return {
                                    id: Date.now() + Math.random(),
                                    source: m.source ? `${cm.sourceCollectionPath} > ${sourceItemName}[0] > ${m.source}` : undefined,
                                    target: m.target ? `${cm.targetCollectionPath} > ${targetItemName}[0] > ${m.target}` : undefined,
                                    type: m.type || 'element',
                                    value: m.value,
                                    transformation: m.transformation || 'direct'
                                };
                            })
                            .filter(m => m.target && m.source);
                        
                        collectionMappings.push(...mappingsInCollection);
                    });
                    
                    convertedMappings = [...staticMappings, ...collectionMappings];
                } else {
                    // Handle flat mapping format (xpath-based)
                    console.log('📋 [Mapping Select] Detected flat mapping format');
                    convertedMappings = Object.entries(mappingData)
                        .map(([targetPath, config]) => ({
                            id: Date.now() + Math.random(),
                            source: config.xpath || config.sourcePath,
                            target: targetPath,
                            type: config.type || 'element',
                            value: config.value,
                            transformation: config.transform || config.transformation || 'direct'
                        }))
                        .filter(mapping => mapping.source); // Only include mappings with a source path
                }
                
                console.log('🔄 [Mapping Select] Converted to', convertedMappings.length, 'visual mappings');
                if (convertedMappings.length > 0) {
                    console.log('Sample mapping:', convertedMappings[0]);
                }
                
                setMappings(convertedMappings);
                setIsMappingFileLoaded(true);
                console.log('✅ [Mapping Select] Successfully loaded mapping JSON from:', fullMapping.mapping_name);
                
                // 🎨 Trigger SVG line update after a short delay
                setTimeout(() => {
                    if (mappingSVGRef.current) {
                        console.log('🎨 [Mapping Select] Triggering SVG line update');
                        mappingSVGRef.current.updateLines();
                    }
                }, 200);
            } else {
                console.warn('⚠️  [Mapping Select] No mapping_json in mapping');
                alert('This mapping does not have mapping JSON saved.');
            }
        } catch (error) {
            console.error('❌ [Mapping Select] Error loading saved mapping JSON:', error);
            console.error('Error details:', error);
            alert('Failed to load saved mapping. Please check the console for details.');
        }
    };

    const handleMappingFile = (content) => {
        if (!content) return;
        
        // 🛑 VALIDATION: Prevent loading mapping file before source
        if (!sourceTree) {
            alert('⚠️ Please upload or select a Source XML file first before loading the mapping file.');
            return;
        }
        
        // 🛑 VALIDATION: Prevent loading mapping file before destination
        if (!targetTree) {
            alert('⚠️ Please upload or select a Destination XML file first before loading the mapping file.');
            return;
        }
        
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
            
            // 🎨 Trigger SVG line update after a short delay
            setTimeout(() => {
                if (mappingSVGRef.current) {
                    console.log('🎨 [Mapping File] Triggering SVG line update');
                    mappingSVGRef.current.updateLines();
                }
            }, 200);
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

            // Prepare context for AI
            const context = {
                sourceSchema: sourceTree.name || 'Source Schema',
                targetSchema: targetTree.name || 'Target Schema',
                existingMappings: mappings.map(m => ({
                    source: m.source,
                    target: m.target
                }))
            };

            // Call AI service
            const result = await generateAISuggestion(
                { name: targetNode.name, path: targetNode.path, type: 'element' },
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
    
    // Helper function to collect only leaf elements (elements with values, not parent containers)
    // Helper function to get parent path context from a full path
    const getParentPath = (fullPath) => {
        if (!fullPath) return '';
        const segments = fullPath.split('/');
        return segments.slice(0, -1).join('/') || '';
    };

    // Helper function to extract example value from a target node
    const getExampleValue = (node) => {
        // Check if the node has an example value property
        if (node.exampleValue) return node.exampleValue;
        if (node.example) return node.example;
        if (node.value) return node.value;
        
        // For some schemas, the example might be in attributes
        if (node.attributes && node.attributes.example) return node.attributes.example;
        
        return null;
    };

    const collectLeafElements = useCallback((tree) => {
        const leafElements = [];
        
        const traverse = (node) => {
            if (node) {
                // A leaf node is one that has no children OR has a value/text content
                const isLeaf = !node.children || node.children.length === 0;
                
                if (isLeaf) {
                    // Include enriched metadata for AI context
                    const fullPath = node.path || node.name;
                    leafElements.push({
                        name: node.name,
                        path: fullPath,
                        type: node.type,
                        isLeaf: true,
                        fullPath: fullPath,
                        pathSegments: fullPath.split('/'),
                        parentContext: getParentPath(fullPath),
                        exampleValue: getExampleValue(node)
                    });
                }
                
                // Continue traversing children if they exist
                if (node.children) {
                    node.children.forEach(traverse);
                }
            }
        };
        
        traverse(tree);
        return leafElements;
    }, []);
    
    const handleBatchAISuggest = useCallback(async () => {
        if (!sourceTree || !targetTree || !hasAIAccess) {
            setShowUpgradePrompt(true);
            return;
        }

        setBatchLoading(true);
        setLoadingMessage('Analyzing schema structure...');
        setLoadingSubMessage('Identifying unmapped leaf elements');
        setLoadingProgress(10);
        
        try {
            // Collect only leaf elements (elements with values, not parent containers)
            const sourceLeafElements = collectLeafElements(sourceTree);
            const targetLeafElements = collectLeafElements(targetTree);
            
            console.log(`📊 Total source leaf elements: ${sourceLeafElements.length}`);
            console.log(`📊 Total target leaf elements: ${targetLeafElements.length}`);
            
            // Filter out already mapped elements
            const mappedSources = new Set(mappings.map(m => m.source));
            const mappedTargets = new Set(mappings.map(m => m.target));
            
            const unmappedSources = sourceLeafElements.filter(el => !mappedSources.has(el.path));
            const unmappedTargets = targetLeafElements.filter(el => !mappedTargets.has(el.path));
            
            console.log(`🔍 Unmapped source leaf elements: ${unmappedSources.length}`);
            console.log(`🔍 Unmapped target leaf elements: ${unmappedTargets.length}`);
            
            setRemainingUnmappedCount(unmappedSources.length);
            setLoadingProgress(20);
            
            // OPTIMIZED: Increased batch size for faster initial pool building
            // More suggestions shown = less frequent reloading = better UX
            const MAX_BATCH_SIZE = 6; // Increased from 3 for faster pool building
            if (unmappedSources.length > MAX_BATCH_SIZE) {
                setLoadingSubMessage(`Found ${unmappedSources.length} unmapped leaf elements. Processing first ${MAX_BATCH_SIZE}...`);
            } else {
                setLoadingSubMessage(`Processing ${unmappedSources.length} unmapped leaf elements...`);
            }
            const sourcesToProcess = unmappedSources.slice(0, MAX_BATCH_SIZE);
            
            // Create proper mapping requests structure for each source element
            // Enhanced context with full path information and leaf node indication
            const optimizedContext = {
                sourceSchema: sourceTree?.name || 'Unknown',
                targetSchema: targetTree?.name || 'Unknown', 
                existingMappings: mappings.map(m => ({ source: m.source, target: m.target })),
                instructions: 'CRITICAL: Only suggest mappings between LEAF NODES (elements with actual values, not parent containers). For ambiguous element names, analyze the FULL PATH context of both source and target to ensure semantic alignment. Consider the hierarchical structure and parent elements when determining confidence.'
            };
            
            setLoadingMessage('Generating AI suggestions...');
            setLoadingSubMessage('This may take a few moments');
            setLoadingProgress(40);
            
            const mappingRequests = sourcesToProcess.map(sourceNode => ({
                sourceNode: sourceNode,
                targetNodes: unmappedTargets,
                context: optimizedContext
            }));
            
            const result = await generateBatchAISuggestions(mappingRequests);
            
            setLoadingProgress(90);
            setLoadingMessage('Processing suggestions...');
            
            // 🔒 CRITICAL: Filter out any non-leaf suggestions and low-confidence suggestions
            const MIN_CONFIDENCE = 50; // Only show suggestions with confidence ≥50%
            const validSuggestions = (result.suggestions || []).filter(suggestion => {
                const sourceIsLeaf = suggestion.sourceElement?.isLeaf !== false;
                const targetIsLeaf = suggestion.targetElement?.isLeaf !== false;
                const hasGoodConfidence = suggestion.confidence >= MIN_CONFIDENCE;
                
                if (!sourceIsLeaf || !targetIsLeaf) {
                    console.warn('⚠️  Filtered out non-leaf suggestion:', {
                        source: suggestion.sourceElement?.name,
                        target: suggestion.targetElement?.name,
                        sourceIsLeaf,
                        targetIsLeaf
                    });
                    return false;
                }
                
                if (!hasGoodConfidence) {
                    console.warn(`⚠️  Filtered out low-confidence suggestion: ${suggestion.sourceElement?.name} → ${suggestion.targetElement?.name} (${suggestion.confidence}%)`);
                    return false;
                }
                
                return true;
            });
            
            const filteredCount = (result.suggestions?.length || 0) - validSuggestions.length;
            if (filteredCount > 0) {
                console.log(`🔒 Filtered ${filteredCount} suggestions (non-leaf or confidence <${MIN_CONFIDENCE}%)`);
            }
            
            setBatchSuggestions(validSuggestions);
            setLoadingProgress(100);
            
            // Short delay to show 100% completion
            setTimeout(() => {
                setBatchLoading(false);
                setShowBatchModal(true);
                setLoadingProgress(null);
                loadingAbortRef.current = false; // Reset abort flag when modal opens
            }, 500);
        } catch (error) {
            console.error('Batch AI suggestion error:', error);
            alert(error.message || 'Failed to generate AI suggestions. Please try again.');
            setShowBatchModal(false);
        } finally {
            setBatchLoading(false);
            setLoadingProgress(null);
        }
    }, [sourceTree, targetTree, mappings, hasAIAccess, collectLeafElements]);

    const handleCancelBatchGeneration = useCallback(() => {
        console.log('🚫 User cancelled AI batch generation');
        setBatchLoading(false);
        setLoadingProgress(null);
        setLoadingMessage('');
        setLoadingSubMessage('');
        setShowBatchModal(false);
        setBatchSuggestions([]);
    }, []);

    const handleAcceptBatchSuggestions = useCallback(async (selectedSuggestions) => {
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

        // Update mappings immediately
        const updatedMappings = [...mappings, ...newMappings];
        updateMappings(updatedMappings);

        // Don't filter suggestions here - let the modal handle hiding accepted items
        // This prevents index mismatch issues

        // Count remaining visible suggestions (not accepted)
        const allAcceptedPaths = new Set([
            ...mappings.map(m => m.source),
            ...newMappings.map(m => m.source)
        ]);
        const visibleCount = batchSuggestions.filter(
            s => !allAcceptedPaths.has(s.sourceElement?.path)
        ).length;

        // Check if we should load more suggestions
        const MAX_BATCH_SIZE = 6; // Increased from 3 for faster pool replenishment
        const MIN_VISIBLE_SUGGESTIONS = 8; // Increased from 5 - start loading earlier
        console.log(`[AI Dynamic Loading] Visible count: ${visibleCount}, Remaining unmapped: ${remainingUnmappedCount}, Selected: ${selectedSuggestions.length}`);
        
        // CONTINUOUS LOADING: Keep loading in background while user works (if less than MIN_VISIBLE and more unmapped exist)
        // OPTIMIZED: Higher threshold (8) means we start loading sooner, reducing user wait time
        if (visibleCount < MIN_VISIBLE_SUGGESTIONS && remainingUnmappedCount > 0) {
            console.log(`⚡ [PROACTIVE LOADING] Visible suggestions (${visibleCount}) below threshold (${MIN_VISIBLE_SUGGESTIONS}). Loading ${MAX_BATCH_SIZE} more in background...`);
            // Load more suggestions in the background
            setIsLoadingMore(true);
            
            try {
                // 🚫 Check if loading was aborted (modal closed)
                if (loadingAbortRef.current) {
                    console.log('🚫 Background loading aborted - modal was closed');
                    setIsLoadingMore(false);
                    return;
                }
                
                // Collect only leaf elements with updated mappings
                const sourceLeafElements = collectLeafElements(sourceTree);
                const targetLeafElements = collectLeafElements(targetTree);
                
                console.log(`🔄 Re-analyzing: ${sourceLeafElements.length} source leaf elements`);
                
                // Filter with updated mappings
                const mappedSources = new Set(updatedMappings.map(m => m.source));
                const mappedTargets = new Set(updatedMappings.map(m => m.target));
                
                const unmappedSources = sourceLeafElements.filter(el => !mappedSources.has(el.path));
                const unmappedTargets = targetLeafElements.filter(el => !mappedTargets.has(el.path));
                
                console.log(`✨ ${unmappedSources.length} unmapped source leaf elements remaining`);
                
                setRemainingUnmappedCount(unmappedSources.length);
                
                // Only load more if there are unmapped elements
                if (unmappedSources.length > 0) {
                    const sourcesToProcess = unmappedSources.slice(0, MAX_BATCH_SIZE);
                    
                    const optimizedContext = {
                        sourceSchema: sourceTree?.name || 'Unknown',
                        targetSchema: targetTree?.name || 'Unknown',
                        existingMappings: updatedMappings.map(m => ({ source: m.source, target: m.target })),
                        instructions: 'CRITICAL: Only suggest mappings between LEAF NODES (elements with actual values, not parent containers). For ambiguous element names, analyze the FULL PATH context of both source and target to ensure semantic alignment. Consider the hierarchical structure and parent elements when determining confidence.'
                    };
                    
                    const mappingRequests = sourcesToProcess.map(sourceNode => ({
                        sourceNode: sourceNode,
                        targetNodes: unmappedTargets,
                        context: optimizedContext
                    }));
                    
                    // 🚫 Check abort flag again before making API call
                    if (loadingAbortRef.current) {
                        console.log('🚫 Background loading aborted before API call - modal was closed');
                        setIsLoadingMore(false);
                        return;
                    }
                    
                    console.log(`⚡ [FAST LOAD] Processing ${mappingRequests.length} suggestions in parallel...`);
                    const result = await generateBatchAISuggestions(mappingRequests);
                    
                    // 🔒 CRITICAL: Filter out any non-leaf suggestions and low-confidence
                    const MIN_CONFIDENCE = 50;
                    const validSuggestions = (result.suggestions || []).filter(suggestion => {
                        const sourceIsLeaf = suggestion.sourceElement?.isLeaf !== false;
                        const targetIsLeaf = suggestion.targetElement?.isLeaf !== false;
                        const hasGoodConfidence = suggestion.confidence >= MIN_CONFIDENCE;
                        
                        if (!sourceIsLeaf || !targetIsLeaf) {
                            console.warn('⚠️  Filtered out non-leaf suggestion during dynamic load');
                            return false;
                        }
                        
                        if (!hasGoodConfidence) {
                            console.warn(`⚠️  Filtered out low-confidence suggestion during dynamic load: ${suggestion.confidence}%`);
                            return false;
                        }
                        
                        return true;
                    });
                    
                    // 🚫 Final check before updating state
                    if (loadingAbortRef.current) {
                        console.log('🚫 Background loading aborted after API response - modal was closed');
                        setIsLoadingMore(false);
                        return;
                    }
                    
                    // Append new suggestions to the list
                    if (validSuggestions.length > 0) {
                        console.log(`[AI Dynamic Loading] Loaded ${validSuggestions.length} new suggestions (confidence ≥${MIN_CONFIDENCE}%)`);
                        setBatchSuggestions(prev => [...prev, ...validSuggestions]);
                    } else {
                        console.log('[AI Dynamic Loading] No new suggestions returned');
                    }
                } else {
                    console.log('[AI Dynamic Loading] No unmapped sources remaining');
                }
            } catch (error) {
                console.error('Error loading more suggestions:', error);
                // Don't show error to user, just stop loading
            } finally {
                setIsLoadingMore(false);
            }
        }
    }, [mappings, sourceTree, targetTree, updateMappings, batchSuggestions, remainingUnmappedCount, collectLeafElements]);

    const handleDeleteBatchSuggestion = useCallback(async (deletedSuggestion, deletedIndex) => {
        console.log(`[AI Delete] Suggestion deleted at index ${deletedIndex}`);
        
        // Count remaining visible suggestions (not accepted, not deleted)
        // This is similar to accept logic but without creating mappings
        const allAcceptedPaths = new Set(mappings.map(m => m.source));
        const visibleCount = batchSuggestions.filter(
            (s, idx) => idx !== deletedIndex && !allAcceptedPaths.has(s.sourceElement?.path)
        ).length;

        // Check if we should load more suggestions
        const MAX_BATCH_SIZE = 6; // Increased from 3 for faster pool replenishment
        const MIN_VISIBLE_SUGGESTIONS = 8; // Increased from 5 - start loading earlier
        console.log(`[AI Delete -> Dynamic Loading] Visible count after delete: ${visibleCount}, Remaining unmapped: ${remainingUnmappedCount}`);
        
        // CONTINUOUS LOADING: Trigger dynamic loading if suggestions are getting low
        // OPTIMIZED: Higher threshold means proactive loading, better UX
        if (visibleCount < MIN_VISIBLE_SUGGESTIONS && remainingUnmappedCount > 0) {
            console.log(`⚡ [PROACTIVE LOADING] Visible (${visibleCount}) below threshold (${MIN_VISIBLE_SUGGESTIONS}). Triggering load of ${MAX_BATCH_SIZE} after delete...`);
            setIsLoadingMore(true);
            
            try {
                // 🚫 Check if loading was aborted (modal closed)
                if (loadingAbortRef.current) {
                    console.log('🚫 Background loading aborted after delete - modal was closed');
                    setIsLoadingMore(false);
                    return;
                }
                
                // Collect only leaf elements
                const sourceLeafElements = collectLeafElements(sourceTree);
                const targetLeafElements = collectLeafElements(targetTree);
                
                console.log(`🔄 Re-analyzing after delete: ${sourceLeafElements.length} source leaf elements`);
                
                // Filter with current mappings
                const mappedSources = new Set(mappings.map(m => m.source));
                const mappedTargets = new Set(mappings.map(m => m.target));
                
                const unmappedSources = sourceLeafElements.filter(el => !mappedSources.has(el.path));
                const unmappedTargets = targetLeafElements.filter(el => !mappedTargets.has(el.path));
                
                console.log(`✨ ${unmappedSources.length} unmapped source leaf elements remaining after delete`);
                
                setRemainingUnmappedCount(unmappedSources.length);
                
                if (unmappedSources.length > 0) {
                    const sourcesToProcess = unmappedSources.slice(0, MAX_BATCH_SIZE);
                    
                    const optimizedContext = {
                        sourceSchema: sourceTree?.name || 'Unknown',
                        targetSchema: targetTree?.name || 'Unknown',
                        existingMappings: mappings.map(m => ({ source: m.source, target: m.target })),
                        instructions: 'CRITICAL: Only suggest mappings between LEAF NODES (elements with actual values, not parent containers). For ambiguous element names, analyze the FULL PATH context of both source and target to ensure semantic alignment. Consider the hierarchical structure and parent elements when determining confidence.'
                    };
                    
                    const mappingRequests = sourcesToProcess.map(sourceNode => ({
                        sourceNode: sourceNode,
                        targetNodes: unmappedTargets,
                        context: optimizedContext
                    }));
                    
                    // 🚫 Check abort flag before API call
                    if (loadingAbortRef.current) {
                        console.log('🚫 Background loading aborted before API call (delete) - modal was closed');
                        setIsLoadingMore(false);
                        return;
                    }
                    
                    console.log(`⚡ [FAST LOAD] Processing ${mappingRequests.length} suggestions in parallel after delete...`);
                    const result = await generateBatchAISuggestions(mappingRequests);
                    
                    // 🔒 CRITICAL: Filter out any non-leaf suggestions and low-confidence
                    const MIN_CONFIDENCE = 50;
                    const validSuggestions = (result.suggestions || []).filter(suggestion => {
                        const sourceIsLeaf = suggestion.sourceElement?.isLeaf !== false;
                        const targetIsLeaf = suggestion.targetElement?.isLeaf !== false;
                        const hasGoodConfidence = suggestion.confidence >= MIN_CONFIDENCE;
                        
                        if (!sourceIsLeaf || !targetIsLeaf) {
                            console.warn('⚠️  Filtered out non-leaf suggestion during delete dynamic load');
                            return false;
                        }
                        
                        if (!hasGoodConfidence) {
                            console.warn(`⚠️  Filtered out low-confidence suggestion during delete load: ${suggestion.confidence}%`);
                            return false;
                        }
                        
                        return true;
                    });
                    
                    // 🚫 Final check before updating state (delete handler)
                    if (loadingAbortRef.current) {
                        console.log('🚫 Background loading aborted after API response (delete) - modal was closed');
                        setIsLoadingMore(false);
                        return;
                    }
                    
                    if (validSuggestions.length > 0) {
                        console.log(`[AI Delete -> Dynamic Loading] Loaded ${validSuggestions.length} new suggestions after delete (confidence ≥${MIN_CONFIDENCE}%)`);
                        setBatchSuggestions(prev => [...prev, ...validSuggestions]);
                    } else {
                        console.log('[AI Delete -> Dynamic Loading] No new suggestions returned after delete');
                    }
                } else {
                    console.log('[AI Delete -> Dynamic Loading] No unmapped sources remaining after delete');
                }
            } catch (error) {
                console.error('Error loading more suggestions after delete:', error);
            } finally {
                setIsLoadingMore(false);
            }
        } else {
            console.log(`[AI Delete -> Dynamic Loading] Skipping dynamic load: visibleCount=${visibleCount}, remaining=${remainingUnmappedCount}`);
        }
    }, [mappings, sourceTree, targetTree, batchSuggestions, remainingUnmappedCount, collectLeafElements]);

    const handleCloseBatchModal = useCallback(() => {
        console.log('🚪 Closing batch modal - aborting background loading');
        loadingAbortRef.current = true; // Signal to abort any ongoing background loading
        setShowBatchModal(false);
        setBatchSuggestions([]);
        setIsLoadingMore(false); // Stop loading indicator
        setRemainingUnmappedCount(0); // Reset remaining count
    }, []);

    const handleRegenerateBatchSuggestions = useCallback(async () => {
        await handleBatchAISuggest();
    }, [handleBatchAISuggest]);

    const handleRegenerateOneSuggestion = useCallback(async (suggestion, index) => {
        console.log(`[AI Regenerate One] Regenerating suggestion at index ${index}`);
        
        try {
            // Get the source element from the suggestion
            const sourceNode = suggestion.sourceElement;
            
            // Collect leaf elements
            const targetLeafElements = collectLeafElements(targetTree);
            
            // Filter out already mapped targets
            const mappedTargets = new Set(mappings.map(m => m.target));
            const unmappedTargets = targetLeafElements.filter(el => !mappedTargets.has(el.path));
            
            console.log(`🔄 Regenerating suggestion for "${sourceNode.name}" with ${unmappedTargets.length} unmapped targets`);
            
            // Create optimized context
            const optimizedContext = {
                sourceSchema: sourceTree?.name || 'Unknown',
                targetSchema: targetTree?.name || 'Unknown',
                existingMappings: mappings.map(m => ({ source: m.source, target: m.target })),
                instructions: 'CRITICAL: Only suggest mappings between LEAF NODES (elements with actual values, not parent containers). For ambiguous element names, analyze the FULL PATH context of both source and target to ensure semantic alignment. Consider the hierarchical structure and parent elements when determining confidence.'
            };
            
            // Create mapping request for single element
            const mappingRequest = {
                sourceNode: sourceNode,
                targetNodes: unmappedTargets,
                context: optimizedContext
            };
            
            // Generate new suggestion
            console.log(`⚡ [REGENERATE ONE] Requesting new suggestion for "${sourceNode.name}"...`);
            const result = await generateBatchAISuggestions([mappingRequest]);
            
            if (result.suggestions && result.suggestions.length > 0) {
                const newSuggestion = result.suggestions[0];
                
                // 🔒 CRITICAL: Validate leaf node and confidence
                const MIN_CONFIDENCE = 50;
                const sourceIsLeaf = newSuggestion.sourceElement?.isLeaf !== false;
                const targetIsLeaf = newSuggestion.targetElement?.isLeaf !== false;
                const hasGoodConfidence = newSuggestion.confidence >= MIN_CONFIDENCE;
                
                if (!sourceIsLeaf || !targetIsLeaf) {
                    console.warn('⚠️  Regenerated suggestion is non-leaf, skipping');
                    return;
                }
                
                if (!hasGoodConfidence) {
                    console.warn(`⚠️  Regenerated suggestion has low confidence (${newSuggestion.confidence}%), skipping`);
                    return;
                }
                
                console.log(`✅ [REGENERATE ONE] New suggestion: ${newSuggestion.targetElement?.name} (confidence: ${newSuggestion.confidence}%)`);
                
                // Replace the suggestion at the specified index
                setBatchSuggestions(prev => {
                    const updated = [...prev];
                    updated[index] = newSuggestion;
                    return updated;
                });
            } else {
                console.log('❌ [REGENERATE ONE] No new suggestion returned');
            }
        } catch (error) {
            console.error('Error regenerating single suggestion:', error);
        }
    }, [sourceTree, targetTree, mappings, collectLeafElements]);

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
                <div style={{ marginBottom: '20px' }}>
                    <Link to="/transformer" className="home-link" style={{ marginTop: '0' }}>← Back to Transformer</Link>
                </div>

                <div className="upload-section">
                {/* Source XML Dropzone */}
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
                
                {/* Destination Schema Dropzone with integrated selector */}
                <FileDropzone 
                    onFileSelect={(files) => handleFile(files[0]?.content, setTargetTree, false)}
                    savedOptionsDropdown={savedMappings.length > 0 ? (
                        <>
                            <div className="dropzone-selector-divider">or select saved</div>
                            <select 
                                value={selectedSavedSchema}
                                onChange={handleSavedSchemaSelect}
                            >
                                <option value="">-- Select Saved Schema --</option>
                                {savedMappings.map(mapping => (
                                    <option key={`schema-${mapping.id}`} value={mapping.id}>
                                        {mapping.mapping_name}
                                    </option>
                                ))}
                            </select>
                        </>
                    ) : null}
                >
                    <div className="icon">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M14 2V8H20" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 13H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M16 17H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                            <path d="M10 9H9H8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                    </div>
                    <h3>Destination Schema</h3>
                    <p>Upload destination XML schema</p>
                </FileDropzone>
                
                {/* Mapping JSON Dropzone with integrated selector */}
                <FileDropzone 
                    onFileSelect={(files) => handleMappingFile(files[0]?.content)}
                    savedOptionsDropdown={savedMappings.length > 0 ? (
                        <>
                            <div className="dropzone-selector-divider">or select saved</div>
                            <select 
                                value={selectedSavedMappingJson}
                                onChange={handleSavedMappingJsonSelect}
                            >
                                <option value="">-- Select Saved Mapping --</option>
                                {savedMappings.map(mapping => (
                                    <option key={`mapping-${mapping.id}`} value={mapping.id}>
                                        {mapping.mapping_name}
                                    </option>
                                ))}
                            </select>
                        </>
                    ) : null}
                >
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

            {/* Loading Spinner for AI Suggestions */}
            <LoadingSpinner
                isOpen={batchLoading}
                message={loadingMessage}
                subMessage={loadingSubMessage}
                progress={loadingProgress}
                onCancel={handleCancelBatchGeneration}
                cancellable={true}
            />

            {/* AI Batch Suggestion Modal */}
            {showBatchModal && (
                <AIBatchSuggestionModal
                    suggestions={batchSuggestions}
                    onAcceptSuggestion={handleAcceptBatchSuggestions}
                    onDeleteSuggestion={handleDeleteBatchSuggestion}
                    onClose={handleCloseBatchModal}
                    onRegenerateAll={handleRegenerateBatchSuggestions}
                    onRegenerateOne={handleRegenerateOneSuggestion}
                    loading={batchLoading}
                    isLoadingMore={isLoadingMore}
                    remainingCount={remainingUnmappedCount}
                    existingMappings={mappings}
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