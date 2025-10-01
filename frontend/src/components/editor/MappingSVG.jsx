import React, { useState, useEffect } from 'react';

function MappingSVG({ mappings, nodeRefs, editorRef }) {
    const [lines, setLines] = useState([]);

    useEffect(() => {
        const drawLines = () => {
            if (!editorRef.current) return;
            const editorRect = editorRef.current.getBoundingClientRect();
            
            const newLines = mappings
                .filter(m => m.source && m.target) // Only draw lines for element-to-element mappings
                .map((m, index) => {
                    const sourceEl = nodeRefs.current.get(m.source);
                    const targetEl = nodeRefs.current.get(m.target);

                    if (!sourceEl || !targetEl) return null;
                    
                    const sourceRect = sourceEl.getBoundingClientRect();
                    const targetRect = targetEl.getBoundingClientRect();

                    // Check if elements are visible
                    if (sourceRect.width === 0 || targetRect.width === 0) return null;
                    
                    const x1 = sourceRect.right - editorRect.left;
                    const y1 = sourceRect.top + sourceRect.height / 2 - editorRect.top;
                    const x2 = targetRect.left - editorRect.left;
                    const y2 = targetRect.top + targetRect.height / 2 - editorRect.top;

                    // Create a curved path
                    const pathData = `M${x1},${y1} C${x1 + 100},${y1} ${x2 - 100},${y2} ${x2},${y2}`;

                    return <path key={`${m.source}-${m.target}`} d={pathData} />;
                })
                .filter(Boolean); // remove nulls

            setLines(newLines);
        };
        
        // Redraw on mappings change or resize
        drawLines();
        
        const sourceTreeEl = editorRef.current?.children[0]?.querySelector('.tree-container');
        const targetTreeEl = editorRef.current?.children[2]?.querySelector('.tree-container');
        
        window.addEventListener('resize', drawLines);
        sourceTreeEl?.addEventListener('scroll', drawLines);
        targetTreeEl?.addEventListener('scroll', drawLines);

        return () => {
            window.removeEventListener('resize', drawLines);
            sourceTreeEl?.removeEventListener('scroll', drawLines);
            targetTreeEl?.removeEventListener('scroll', drawLines);
        };
    }, [mappings, nodeRefs, editorRef]);


    return (
        <svg className="mapping-svg-canvas">
            {lines}
        </svg>
    );
}

export default MappingSVG;