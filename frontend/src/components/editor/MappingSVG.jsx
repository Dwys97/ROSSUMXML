import React, { useEffect, useState, useImperativeHandle, forwardRef, useCallback } from 'react';

const MappingSVG = forwardRef(({ mappings, nodeRefs, editorRef, sourceTreeRef, targetTreeRef }, ref) => {
    const [lines, setLines] = useState([]);

    const updateLines = useCallback(() => {
        if (!editorRef.current || !sourceTreeRef.current || !targetTreeRef.current) {
            console.warn('⚠️ [SVG] Missing refs:', {
                editor: !!editorRef.current,
                sourceTree: !!sourceTreeRef.current,
                targetTree: !!targetTreeRef.current
            });
            return;
        }

        console.log('🎨 [SVG] updateLines called with', mappings.length, 'mappings');
        console.log('📊 [SVG] Available node refs:', nodeRefs.current.size);

        const svgRect = editorRef.current.getBoundingClientRect();
        const sourceTreeRect = sourceTreeRef.current.getBoundingClientRect();
        const targetTreeRect = targetTreeRef.current.getBoundingClientRect();
        
        const newLines = mappings
            .map((m, idx) => {
                if (m.type === 'custom_element' || !m.source) return null;
                
                const sEl = nodeRefs.current.get(m.source);
                const tEl = nodeRefs.current.get(m.target);

                if (!sEl || !tEl) {
                    console.warn(`⚠️ [SVG] Missing node ref for mapping ${idx}:`, {
                        source: m.source,
                        target: m.target,
                        hasSource: !!sEl,
                        hasTarget: !!tEl
                    });
                    return null;
                }

                const sRect = sEl.getBoundingClientRect();
                const tRect = tEl.getBoundingClientRect();
                
                if (sRect.width === 0 || tRect.width === 0) return null;

                // Check if source node is visible within its tree container
                const sourceVisible = sRect.bottom > sourceTreeRect.top && sRect.top < sourceTreeRect.bottom;
                // Check if target node is visible within its tree container
                const targetVisible = tRect.bottom > targetTreeRect.top && tRect.top < targetTreeRect.bottom;
                
                // Only draw the line if both endpoints are visible
                if (!sourceVisible || !targetVisible) return null;

                const x1 = sRect.right - svgRect.left;
                const y1 = sRect.top + sRect.height / 2 - svgRect.top;
                const x2 = tRect.left - svgRect.left;
                const y2 = tRect.top + tRect.height / 2 - svgRect.top;
                
                const d = `M${x1},${y1} C${x1 + 100},${y1} ${x2 - 100},${y2} ${x2},${y2}`;
                return { id: `${m.source}-${m.target}`, d };
            })
            .filter(Boolean);
        
        console.log('✅ [SVG] Drew', newLines.length, 'lines out of', mappings.length, 'mappings');
        setLines(newLines);
    }, [mappings, nodeRefs, editorRef, sourceTreeRef, targetTreeRef]);

    useImperativeHandle(ref, () => ({
        updateLines
    }));

    useEffect(() => {
        // A short timeout to ensure the DOM has settled before the initial drawing
        const timeoutId = setTimeout(updateLines, 50);

        // Redraw on window resize
        window.addEventListener('resize', updateLines);
        
        // Use ResizeObserver to watch for layout changes within the editor
        const observer = new ResizeObserver(updateLines);
        const editorElement = editorRef.current;
        if (editorElement) {
            observer.observe(editorElement);
        }

        const sourceTree = sourceTreeRef.current;
        const targetTree = targetTreeRef.current;

        if (sourceTree) {
            sourceTree.addEventListener('scroll', updateLines);
        }
        if (targetTree) {
            targetTree.addEventListener('scroll', updateLines);
        }

        return () => {
            clearTimeout(timeoutId);
            window.removeEventListener('resize', updateLines);
            if (editorElement) {
               observer.unobserve(editorElement);
            }
            if (sourceTree) {
                sourceTree.removeEventListener('scroll', updateLines);
            }
            if (targetTree) {
                targetTree.removeEventListener('scroll', updateLines);
            }
        };
    }, [mappings, nodeRefs, editorRef, sourceTreeRef, targetTreeRef, updateLines]);

    return (
        <svg className="mapping-svg">
            {lines.map(line => (
                <path
                    key={line.id}
                    d={line.d}
                    stroke="#2ecc71"
                    strokeWidth="2.5"
                    fill="none"
                    strokeDasharray="8 4"
                />
            ))}
        </svg>
    );
});

export default MappingSVG;