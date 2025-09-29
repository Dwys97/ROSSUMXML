document.addEventListener('DOMContentLoaded', () => {
    const dropSource = document.getElementById('dropSource');
    const inputXmlTextarea = document.getElementById('inputXml');
    const outputXmlTextarea = document.getElementById('outputXml');
    const transformBtn = document.getElementById('transformBtn');
    const downloadLink = document.getElementById('downloadLink');
    const copyBtn = document.getElementById('copyBtn');
    const removeEmptyTagsCheckbox = document.getElementById('removeEmptyTagsCheckbox');

    let sourceFiles = [];
    let destinationXmlContent = null;
    let jsonMappingContent = null;

    const dummySetup = (id, handler, isJson = false) => {
        const el = document.getElementById(id);
        const inp = document.createElement('input');
        inp.type = 'file';
        el.addEventListener('click', () => inp.click());
        inp.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (ev) => handler(isJson ? JSON.parse(ev.target.result) : ev.target.result);
                reader.readAsText(file);
            }
        });
    };

    dummySetup('dropSource', (content) => {
        sourceFiles = [content];
        inputXmlTextarea.value = content;
    }, false);

    dummySetup('dropDest', (content) => {
        destinationXmlContent = content;
    }, false);

    dummySetup('dropMap', (content) => {
        jsonMappingContent = content;
    }, true);

    transformBtn.addEventListener('click', async () => {
        if (!sourceFiles.length || !destinationXmlContent || !jsonMappingContent) {
            alert('Please provide all required files.');
            return;
        }

        try {
            // Call raw XML endpoint
            const response = await fetch("http://localhost:3000/", {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sourceXml: sourceFiles[0],
                    destinationXml: destinationXmlContent,
                    mappingJson: jsonMappingContent,
                    removeEmptyTags: removeEmptyTagsCheckbox.checked
                })
            });

            if (!response.ok) throw new Error('Server error during transformation');

            // Receive raw XML directly
            const transformed = await response.text();
            outputXmlTextarea.value = transformed;

            downloadLink.href = 'data:text/xml;charset=utf-8,' + encodeURIComponent(transformed);
            downloadLink.download = 'transformed.xml';
            downloadLink.style.display = 'block';
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });

    copyBtn.addEventListener('click', () => {
        if (outputXmlTextarea.value) {
            navigator.clipboard.writeText(outputXmlTextarea.value);
        }
    });
});

