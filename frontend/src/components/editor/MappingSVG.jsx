import React, { useEffect, useState } from 'react';

function MappingSVG({ mappings, nodeRefs, editorRef, sourceTreeRef, targetTreeRef }) {
    const [lines, setLines] = useState([]);

    useEffect(() => {
        const updateLines = () => {
            if (!editorRef.current) return;

            const svgRect = editorRef.current.getBoundingClientRect();
            
            const newLines = mappings
                .map(m => {
                    if (m.type === 'custom_element' || !m.source) return null;
                    
                    const sEl = nodeRefs.current.get(m.source);
                    const tEl = nodeRefs.current.get(m.target);

                    if (!sEl || !tEl) return null;

                    const sRect = sEl.getBoundingClientRect();
                    const tRect = tEl.getBoundingClientRect();
                    
                    if (sRect.width === 0 || tRect.width === 0) return null;

                    const x1 = sRect.right - svgRect.left;
                    const y1 = sRect.top + sRect.height / 2 - svgRect.top;
                    const x2 = tRect.left - svgRect.left;
                    const y2 = tRect.top + tRect.height / 2 - svgRect.top;
                    
                    const d = `M${x1},${y1} C${x1 + 100},${y1} ${x2 - 100},${y2} ${x2},${y2}`;
                    return { id: `${m.source}-${m.target}`, d };
                })
                .filter(Boolean);
            
            setLines(newLines);
        };

        // Use a timeout to ensure DOM has settled before drawing
        const timeoutId = setTimeout(updateLines, 50);

        const sourceTree = sourceTreeRef.current;
        const targetTree = targetTreeRef.current;

        // Redraw on window resize and scroll
        window.addEventListener('resize', updateLines);
        sourceTree?.addEventListener('scroll', updateLines);
        targetTree?.addEventListener('scroll', updateLines);

        // Use ResizeObserver to watch for layout changes within the editor
        const observer = new ResizeObserver(updateLines);
        if (editorRef.current) {
            observer.observe(editorRef.current);
        }

        return () => {
            clearTimeout(timeoutId);
            window.removeEventListener('resize', updateLines);
            sourceTree?.removeEventListener('scroll', updateLines);
            targetTree?.removeEventListener('scroll', updateLines);
            if (editorRef.current) {
               observer.unobserve(editorRef.current);
            }
        };
    }, [mappings, nodeRefs, editorRef, sourceTreeRef, targetTreeRef]);

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
}

export default MappingSVG;