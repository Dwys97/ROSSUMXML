document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const dropXsd = document.getElementById('dropXsd');
    const outputXmlTextarea = document.getElementById('outputXml');
    const transformBtn = document.getElementById('transformBtn');
    let xsdSchemaContent = null;

    // Create a hidden file input for the XSD dropzone
    const xsdInput = document.createElement('input');
    xsdInput.type = 'file';
    xsdInput.accept = '.xsd';
    xsdInput.classList.add('hidden');
    document.body.appendChild(xsdInput);

    // --- Core validation function ---
    const validateOutput = async () => {
        const xmlContent = outputXmlTextarea.value;

        // Do nothing if no XSD is loaded or there is no output to check
        if (!xsdSchemaContent || !xmlContent) {
            return;
        }

        // --- FIX: Check if the validation library has loaded before using it ---
        if (typeof window.XSDValidator === 'undefined') {
            const errorMsg = 'Validation library failed to load. Please check your internet connection or ad-blocker.';
            console.error(errorMsg);
            alert(`❌ Validation Error: ${errorMsg}`);
            return;
        }

        try {
            const validationResult = await window.XSDValidator.validate(xmlContent, xsdSchemaContent);
            if (validationResult.errors.length === 0) {
                alert('✅ Output XML is VALID against the provided XSD schema.');
            } else {
                console.error("XSD Validation Errors:", validationResult.errors);
                alert(`❌ Output XML is INVALID.\n\nReason: ${validationResult.errors[0].message}\n\n(Check the browser console for all errors)`);
            }
        } catch (err) {
            console.error("Validation library error:", err);
            alert('An error occurred during XSD validation. Check the console.');
        }
    };

    // --- Event Listener Setup ---

    // 1. Handle XSD file upload
    const readXsdFile = (file) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            xsdSchemaContent = e.target.result;
            // If there's already XML in the output, re-validate it immediately
            if (outputXmlTextarea.value) {
                validateOutput();
            }
        };
        reader.readAsText(file);
    };

    // Wire up the dropzone events
    dropXsd.addEventListener('click', () => xsdInput.click());
    xsdInput.addEventListener('change', () => {
        if (xsdInput.files.length > 0) readXsdFile(xsdInput.files[0]);
    });
    dropXsd.addEventListener('dragover', (e) => { e.preventDefault(); dropXsd.classList.add('dragover'); });
    dropXsd.addEventListener('dragleave', () => dropXsd.classList.remove('dragover'));
    dropXsd.addEventListener('drop', (e) => {
        e.preventDefault();
        dropXsd.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) readXsdFile(e.dataTransfer.files[0]);
    });

    // 2. Handle the Transform button click
    transformBtn.addEventListener('click', () => {
        // Use a small delay to ensure script.js has finished updating the textarea
        setTimeout(validateOutput, 100);
    });
});