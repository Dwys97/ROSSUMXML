document.addEventListener('DOMContentLoaded', () => {
  // --- DOM Elements ---
  const sourceInput = document.getElementById('sourceXmlFile');
  const targetInput = document.getElementById('targetXmlFile');
  const mappingInput = document.getElementById('mappingFile');
  const dropSource = document.getElementById('dropSourceSettings');
  const dropTarget = document.getElementById('dropTargetSettings');
  const dropMap = document.getElementById('dropMapSettings');
  const sourceTreeContainer = document.getElementById('sourceTree');
  const targetTreeContainer = document.getElementById('targetTree');
  const mappingSVG = document.getElementById('mappingSVG');
  const loadedMappingsList = document.getElementById('loadedMappingsList');
  const saveMappingsBtn = document.getElementById('saveMappingsBtn');
  const undoBtn = document.getElementById('undoBtn');
  const sourceSearch = document.getElementById('sourceSearch');
  const targetSearch = document.getElementById('targetSearch');
  const clearSourceSearchBtn = document.getElementById('clearSourceSearchBtn');
  const clearTargetSearchBtn = document.getElementById('clearTargetSearchBtn');

  // --- tiny injected styles for the dot + flash (safe, minimal) ---
  (function injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
.mapped-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-left: 6px;
  border-radius: 50%;
  background-color: #2ecc71;
  vertical-align: middle;
  box-shadow: 0 0 4px rgba(46,204,113,0.8);
}
.tree-node.has-mapped-children {
    background-color: rgba(46, 204, 113, 0.4); /* green flash */
    transition: background-color 0.5s ease-in-out;
}

.tree-node {
    transition: background-color 0.5s ease-in-out; /* ensures smooth revert */
}

@keyframes flashMapped {
  0% { background-color: rgba(46,204,113,0.25); }
  100% { background-color: transparent; }
}
.drop-confirm-tooltip {
    position: absolute;
    background-color: #1e2a3a; /* CHANGED to match your card background */
    color: #e0e1dd; /* ADDED to make text light */
    border: 1px solid #3a506b; /* CHANGED to match your card border */
    padding: 8px 12px;
    border-radius: 4px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    z-index: 1000;
    font-size: 13px;
    white-space: nowrap;
}
        `;
    document.head.appendChild(style);
  })();

  // --- State ---
  let sourceTreeData = null;
  let targetTreeData = null;
  let currentMappings = { mappings: [] };
  const mappingsHistory = [];
  const parser = new DOMParser();
  let selectedSourceCollection = null;
  let selectedTargetCollection = null;

  // --- Core Functions ---
  function drawMappings() {
    requestAnimationFrame(() => {
      mappingSVG.innerHTML = '';
      if (!currentMappings.mappings) return;
      const svgRect = mappingSVG.getBoundingClientRect();
      currentMappings.mappings.forEach(m => {
        if (m.type === 'custom_element' || !m.source) return;
        const sEl = sourceTreeContainer.querySelector(`[data-path="${m.source}"]`);
        const tEl = targetTreeContainer.querySelector(`[data-path="${m.target}"]`);
        if (!sEl || !tEl) return;

        // If either endpoint is inside a collapsed parent, skip drawing
        if (!isNodeVisible(sEl) || !isNodeVisible(tEl)) return;

        const sRect = sEl.getBoundingClientRect();
        const tRect = tEl.getBoundingClientRect();

        // Skip if either element is not visible (width or height zero)
        if (sRect.width === 0 || sRect.height === 0 || tRect.width === 0 || tRect.height === 0) {
          return; // skip drawing this line
        }

        const x1 = sRect.right - svgRect.left;
        const y1 = sRect.top + sRect.height / 2 - svgRect.top;
        const x2 = tRect.left - svgRect.left;
        const y2 = tRect.top + tRect.height / 2 - svgRect.top;
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M${x1},${y1} C${x1 + 100},${y1} ${x2 - 100},${y2} ${x2},${y2}`);
        path.setAttribute('stroke', '#2ecc71');
        path.setAttribute('stroke-width', '2.5');
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke-dasharray', '8 4'); // 8px dash, 4px gap
        mappingSVG.appendChild(path);
      });
    });
  }

  function isNodeVisible(el) {
    if (!el) return false;
    let parent = el.closest('.tree-node-item');
    while (parent) {
      if (parent.classList.contains('collapsed')) {
        return false;
      }
      parent = parent.parentElement ? parent.parentElement.closest('.tree-node-item') : null;
    }
    return true;
  }

  function hasMappedDescendants(path, isSource) {
    return currentMappings.mappings.some(m => {
      const checkPath = isSource ? m.source : m.target;
      return checkPath && checkPath.startsWith(path);
    });
  }

  function updateParentMappingMarkers() {
    document.querySelectorAll('.tree-node').forEach(div => {
      const path = div.dataset.path;
      if (!path) return;
      const parentLi = div.closest('.tree-node-item');
      if (!parentLi) return;
      const isSourceNode = div.closest('#sourceTree') !== null;
      const marker = div.querySelector('.mapped-dot');

      if (parentLi.classList.contains('collapsed') && hasMappedDescendants(path, isSourceNode)) {
        if (!marker) {
          const dot = document.createElement('span');
          dot.classList.add('mapped-dot');
          div.appendChild(dot);
        }
      } else {
        if (marker) marker.remove();
      }
    });
  }

  function updateMappedNodeStyles() {
    document.querySelectorAll('.tree-node.is-mapped').forEach(n => n.classList.remove('is-mapped'));
    const mappedSourcePaths = new Set(currentMappings.mappings.filter(m => m.source).map(m => m.source));
    const mappedTargetPaths = new Set(currentMappings.mappings.map(m => m.target));
    mappedSourcePaths.forEach(path => {
      const el = sourceTreeContainer.querySelector(`[data-path="${path}"]`);
      if (el) el.classList.add('is-mapped');
    });
    mappedTargetPaths.forEach(path => {
      const el = targetTreeContainer.querySelector(`[data-path="${path}"]`);
      if (el) el.classList.add('is-mapped');
    });
  }

  function updateTargetValuesAndColors() {
    if (!targetTreeContainer) return;
    const mappedTargets = new Map();
    currentMappings.mappings.forEach(m => { if (m.target) mappedTargets.set(m.target, m); });
    targetTreeContainer.querySelectorAll('.tree-node').forEach(div => {
      const path = div.dataset.path;
      if (!path) return;
      const valueSpan = div.querySelector('.node-value');
      if (!valueSpan) return;

      if (mappedTargets.has(path)) {
        const mapping = mappedTargets.get(path);
        valueSpan.style.color = '#2ecc71';

        if (mapping.type === 'custom_element' && mapping.value !== undefined) {
          valueSpan.textContent = `: "${mapping.value}"`;
        } else {
          const sourceNode = sourceTreeContainer.querySelector(`[data-path="${mapping.source}"]`);
          const sourceValueSpan = sourceNode ? sourceNode.querySelector('.node-value') : null;

          if (sourceValueSpan && sourceValueSpan.textContent) {
            valueSpan.textContent = sourceValueSpan.textContent;
          } else {
            const originalText = valueSpan.dataset.originalValue || '';
            valueSpan.textContent = originalText;
          }
        }
      } else {
        valueSpan.style.color = 'grey';
        const originalText = valueSpan.dataset.originalValue || '';
        valueSpan.textContent = originalText;
      }
    });
  }

  function renderMappingsList() {
    loadedMappingsList.innerHTML = '';
    updateMappedNodeStyles();
    if (!currentMappings.mappings || currentMappings.mappings.length === 0) {
      loadedMappingsList.innerHTML = '<p style="text-align: center; color: #a5a5a5;">No mappings created yet.</p>';
    }
    currentMappings.mappings.forEach((mapping, i) => {
      const div = document.createElement('div');
      div.classList.add('mapping-item');
      const text = document.createElement('span');
      const targetName = mapping.target.split(' > ').pop().replace(/\[.*?\]/g, '');
      if (mapping.type === 'custom_element') {
        text.textContent = `"${mapping.value}" → ${targetName}`;
      } else {
        const sourceName = mapping.source.split(' > ').pop().replace(/\[.*?\]/g, '');
        text.textContent = `${sourceName} → ${targetName}`;
      }
      const removeBtn = document.createElement('button');
      removeBtn.textContent = '×';
      removeBtn.onclick = () => {
        mappingsHistory.push(JSON.parse(JSON.stringify(currentMappings.mappings)));
        currentMappings.mappings.splice(i, 1);
        renderMappingsList();
        drawMappings();
      };
      div.appendChild(text);
      div.appendChild(removeBtn);
      loadedMappingsList.appendChild(div);
    });

    updateTargetValuesAndColors();
    updateParentMappingMarkers();
  }

  // Create Clear All button
  const clearAllBtn = document.createElement('button');
  clearAllBtn.textContent = 'Clear All Mappings';
  clearAllBtn.style.margin = '10px';
  clearAllBtn.style.padding = '6px 12px';
  clearAllBtn.style.backgroundColor = '#e74c3c';
  clearAllBtn.style.color = 'white';
  clearAllBtn.style.border = 'none';
  clearAllBtn.style.borderRadius = '4px';
  clearAllBtn.style.cursor = 'pointer';
  loadedMappingsList.parentNode.insertBefore(clearAllBtn, loadedMappingsList);

  clearAllBtn.addEventListener('click', () => {
    if (currentMappings.mappings.length === 0) {
      alert('No mappings to clear.');
      return;
    }
    if (confirm('Are you sure you want to clear all mappings?')) {
      mappingsHistory.push(JSON.parse(JSON.stringify(currentMappings.mappings)));
      currentMappings.mappings = [];
      renderMappingsList();
      drawMappings();
    }
  });

  function parseXmlToTree(xmlString) {
    const doc = parser.parseFromString(xmlString, 'text/xml');
    if (!doc || doc.getElementsByTagName('parsererror').length > 0) {
      console.error('XML Parsing Error'); return null;
    }
    const startNode = doc.querySelector('annotation > content') || doc.documentElement;

    function getNodeName(node) {
      const schemaId = node.getAttribute('schema_id');
      const localName = node.localName || node.nodeName;
      const value = (node.textContent || '').trim();
      let displayValue = '';
      if (node.childElementCount === 0 && value) {
        const truncatedValue = value.length > 60 ? `${value.substring(0, 57)}...` : value;
        displayValue = `<span style="color: #16a085; font-style: italic;">: "${truncatedValue}"</span>`;
      }
      const namePart = `<strong>${localName}</strong>`;
      const schemaPart = schemaId ? `<span style="color: #7f8c8d;">[schema_id=${schemaId}]</span>` : '';
      return `${namePart} ${schemaPart} ${displayValue}`.trim();
    }

    function getNodePathName(node) {
      const schemaId = node.getAttribute('schema_id');
      const localName = node.localName || node.nodeName;
      return schemaId ? `${localName}[schema_id=${schemaId}]` : localName;
    }

    function processChildren(parentNode, parentPath, siblingCounters = {}) {
      return Array.from(parentNode.children).map(childNode => {
        const pathName = getNodePathName(childNode);
        const count = siblingCounters[pathName] || 0;
        const indexedNameForPath = `${pathName}[${count}]`;
        siblingCounters[pathName] = count + 1;
        const childPath = parentPath ? `${parentPath} > ${indexedNameForPath}` : indexedNameForPath;
        return {
          name: getNodeName(childNode),
          path: childPath,
          pathName: pathName,
          children: processChildren(childNode, childPath, {}) // New object ensures sibling count resets for each child level
        };
      });
    }

    const rootPathName = getNodePathName(startNode);
    const rootPath = `${rootPathName}[0]`;
    return {
      name: getNodeName(startNode),
      path: rootPath,
      pathName: rootPathName,
      children: processChildren(startNode, rootPath)
    };
  }

  function renderTree(treeData, container, isSource) {
    if (!treeData) { container.innerHTML = ''; return; }
    container.innerHTML = '';
    const ul = document.createElement('ul');
    ul.classList.add('tree-root');

    function renderNode(node, parentUl) {
      const li = document.createElement('li');
      li.classList.add('tree-node-item');
      const div = document.createElement('div');
      div.classList.add('tree-node');
      div.dataset.path = node.path;
      div.draggable = isSource;

      const isCollectionNode = node.path.endsWith('[0]') && node.children.length > 0;

      if (isCollectionNode) {
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'collection-selector';
        checkbox.dataset.path = node.path;
        checkbox.dataset.name = node.pathName;

        const selectedCollection = isSource ? selectedSourceCollection : selectedTargetCollection;
        if (selectedCollection && selectedCollection.path === node.path) {
          checkbox.checked = true;
          div.classList.add('is-collection-root');
        }

        checkbox.addEventListener('change', (e) => handleCollectionSelection(e.target, isSource));
        div.appendChild(checkbox);
      }

      const labelSpan = document.createElement('span');
      labelSpan.className = 'node-label';
      const valueMatch = node.name.match(/(<span style="color: #16a085; font-style: italic;">: ".*?"<\/span>)/);
      const namePartHTML = valueMatch ? node.name.substring(0, valueMatch.index) : node.name;
      labelSpan.innerHTML = namePartHTML;
      div.appendChild(labelSpan);

      if (valueMatch) {
        const valueSpan = document.createElement('span');
        valueSpan.className = 'node-value';
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = valueMatch[0];
        const originalText = tempDiv.textContent;
        valueSpan.textContent = originalText;
        valueSpan.dataset.originalValue = originalText;
        valueSpan.style.color = 'grey';
        div.appendChild(valueSpan);
      }

      if (node.children.length > 0) {
        const toggle = document.createElement('span');
        toggle.textContent = '▾';
        toggle.classList.add('toggle-icon');
        toggle.onclick = (e) => {
          e.stopPropagation();
          li.classList.toggle('collapsed');
          const collapsed = li.classList.contains('collapsed');
          toggle.textContent = collapsed ? '▸' : '▾';

          if (collapsed && hasMappedDescendants(node.path, isSource)) {
            setTimeout(() => {
              div.classList.add('has-mapped-children');
              setTimeout(() => div.classList.remove('has-mapped-children'), 500);
            }, 100);
          }

          updateParentMappingMarkers();
          drawMappings();
        };
        div.appendChild(toggle);
      }

      if (!isSource) {
        const customValueBtn = document.createElement('button');
        customValueBtn.textContent = '✎';
        customValueBtn.classList.add('custom-value-btn');
        customValueBtn.onclick = (e) => { e.stopPropagation(); handleSetCustomValue(node.path); };
        div.appendChild(customValueBtn);
      }

      li.appendChild(div);

      if (node.children.length > 0) {
        const subUl = document.createElement('ul');
        node.children.forEach(child => renderNode(child, subUl));
        li.appendChild(subUl);
      }

      parentUl.appendChild(li);
    }

    renderNode(treeData, ul);
    container.appendChild(ul);
    addDragDropListeners(container, isSource);
    updateParentMappingMarkers();
  }

  function handleCollectionSelection(checkbox, isSource) {
    const collectionState = checkbox.checked ? {
      path: checkbox.dataset.path,
      name: checkbox.dataset.name,
      parentPath: checkbox.dataset.path.split(' > ').slice(0, -1).join(' > ')
    } : null;
    if (isSource) selectedSourceCollection = collectionState;
    else selectedTargetCollection = collectionState;

    [sourceTreeContainer, targetTreeContainer].forEach((container, index) => {
      const currentSelection = index === 0 ? selectedSourceCollection : selectedTargetCollection;
      container.querySelectorAll('.tree-node.is-collection-root').forEach(n => n.classList.remove('is-collection-root'));
      container.querySelectorAll('.collection-selector').forEach(cb => {
        if (currentSelection && cb.dataset.path === currentSelection.path) {
          cb.checked = true;
          cb.closest('.tree-node').classList.add('is-collection-root');
        } else {
          cb.checked = false;
        }
      });
    });
  }

  function showDropConfirmation(targetEl, existingMapping, onConfirm, onCancel) {
    const existingTooltip = document.querySelector('.drop-confirm-tooltip');
    if (existingTooltip) existingTooltip.remove();

    const tooltip = document.createElement('div');
    tooltip.className = 'drop-confirm-tooltip';
    tooltip.innerHTML = `
            <span>Already mapped to "<strong>${existingMapping.source || existingMapping.value}</strong>"</span>
            <button class="replace-btn" style="margin-left:8px;color:white;background-color:#2ecc71;border:none;padding:2px 6px;border-radius:3px;cursor:pointer;">Replace</button>
            <button class="cancel-btn" style="margin-left:4px;color:white;background-color:#e74c3c;border:none;padding:2px 6px;border-radius:3px;cursor:pointer;">Cancel</button>
        `;
    document.body.appendChild(tooltip);

    const rect = targetEl.getBoundingClientRect();
    tooltip.style.top = `${Math.max(window.scrollY + rect.top - tooltip.offsetHeight - 4, 0)}px`;
    tooltip.style.left = `${Math.max(window.scrollX + rect.left, 0)}px`;

    tooltip.querySelector('.replace-btn').onclick = () => { tooltip.remove(); onConfirm(); };
    tooltip.querySelector('.cancel-btn').onclick = () => { tooltip.remove(); if (onCancel) onCancel(); };

    // Auto-dismiss tooltip after 5s
    setTimeout(() => { tooltip.remove(); }, 5000);
  }

  function addDragDropListeners(container, isSource) {
    if (isSource) {
      container.querySelectorAll('[draggable="true"]').forEach(el => {
        el.addEventListener('dragstart', e => e.dataTransfer.setData('text/plain', el.dataset.path));
      });
    } else {
      container.querySelectorAll('.tree-node').forEach(el => {
        el.addEventListener('dragover', e => e.preventDefault());
        el.addEventListener('drop', e => {
          e.preventDefault();
          const sourcePath = e.dataTransfer.getData('text/plain');
          const targetPath = el.dataset.path;
          const existingMapping = currentMappings.mappings.find(m => m.target === targetPath);

          const applyMapping = () => {
            mappingsHistory.push(JSON.parse(JSON.stringify(currentMappings.mappings)));
            currentMappings.mappings = currentMappings.mappings.filter(m => m.target !== targetPath);
            currentMappings.mappings.push({ source: sourcePath, target: targetPath, type: "element" });
            renderMappingsList();
            drawMappings();
            el.classList.add('drop-flash');
            setTimeout(() => el.classList.remove('drop-flash'), 600);
          };

          if (existingMapping) {
            showDropConfirmation(el, existingMapping, applyMapping);
          } else {
            applyMapping();
          }
        });
      });
    }
  }

  function handleSourceFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      sourceTreeData = parseXmlToTree(e.target.result);
      renderTree(sourceTreeData, sourceTreeContainer, true);
    };
    reader.readAsText(file);
  }

  function handleTargetFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      targetTreeData = parseXmlToTree(e.target.result);
      renderTree(targetTreeData, targetTreeContainer, false);
    };
    reader.readAsText(file);
  }

  function handleMappingFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const imported = JSON.parse(e.target.result);
        selectedSourceCollection = null;
        selectedTargetCollection = null;

        const collectionMappings = (imported.collectionMappings || []).flatMap(cm => {
          if (!selectedSourceCollection && cm.sourceCollectionPath) {
            const rawSourceItemName = (cm.sourceItemElementName || '').split('[')[0] || '';
            selectedSourceCollection = {
              path: `${cm.sourceCollectionPath} > ${rawSourceItemName}[0]`,
              name: cm.sourceItemElementName,
              parentPath: cm.sourceCollectionPath
            };
          }
          if (!selectedTargetCollection && cm.targetCollectionPath) {
            const rawTargetItemName = (cm.targetItemElementName || '').split('[')[0] || cm.targetItemElementName;
            selectedTargetCollection = {
              path: `${cm.targetCollectionPath} > ${rawTargetItemName}[0]`,
              name: cm.targetItemElementName,
              parentPath: cm.targetCollectionPath
            };
          }
          return (cm.mappings || []).map(m => {
            const sourceRelative = m.source ? ` > ${m.source}` : '';
            const targetRelative = m.target ? ` > ${m.target}` : '';
            const rawSourceItemName = (cm.sourceItemElementName || '').split('[')[0] || cm.sourceItemElementName;
            const rawTargetItemName = (cm.targetItemElementName || '').split('[')[0] || cm.targetItemElementName;
            return {
              source: `${cm.sourceCollectionPath} > ${rawSourceItemName}[0]${sourceRelative}`,
              target: `${cm.targetCollectionPath} > ${rawTargetItemName}[0]${targetRelative}`,
              type: m.type || 'element'
            };
          });
        });

        currentMappings.mappings = (imported.staticMappings || []).concat(collectionMappings);

        if (imported.rootElement) currentMappings.rootElement = imported.rootElement;

        mappingsHistory.length = 0;
        renderMappingsList();
        drawMappings();
        renderTree(targetTreeData, targetTreeContainer, false);
        renderTree(sourceTreeData, sourceTreeContainer, true);
        renderTree(targetTreeData, targetTreeContainer, false);
      } catch (err) { console.error('Invalid mapping JSON:', err); }
    };
    reader.readAsText(file);
  }

  function handleSetCustomValue(targetPath) {
    const existing = currentMappings.mappings.find(m => m.target === targetPath);
    const userValue = prompt('Enter custom value:', existing ? existing.value : '');
    if (userValue !== null && userValue.trim() !== "") {
      mappingsHistory.push(JSON.parse(JSON.stringify(currentMappings.mappings)));
      currentMappings.mappings = currentMappings.mappings.filter(m => m.target !== targetPath);
      currentMappings.mappings.push({ type: "custom_element", value: userValue, target: targetPath });
      renderMappingsList();
      drawMappings();
    }
  }

  function setupDropzone(dropzone, input, handler) {
    const filenameNote = dropzone.querySelector('.drop-filename') || document.createElement('div');
    if (!filenameNote.classList.contains('drop-filename')) {
      filenameNote.classList.add('drop-filename');
      dropzone.appendChild(filenameNote);
    }
    const originalParagraph = dropzone.querySelector('p');
    dropzone.addEventListener('click', () => input.click());
    dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    function handleFile(file) {
      dropzone.classList.add('file-uploaded');
      if (originalParagraph) originalParagraph.style.display = 'none';
      filenameNote.innerHTML = `✔ ${file.name}`;
      handler(file);
    }
    dropzone.addEventListener('drop', e => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        input.files = e.dataTransfer.files;
        handleFile(e.dataTransfer.files[0]);
      }
    });
    input.addEventListener('change', () => {
      if (input.files.length > 0) {
        handleFile(input.files[0]);
      }
    });
  }

  setupDropzone(dropSource, sourceInput, handleSourceFile);
  setupDropzone(dropTarget, targetInput, handleTargetFile);
  setupDropzone(dropMap, mappingInput, handleMappingFile);

  saveMappingsBtn.addEventListener('click', () => {
    const staticMappings = [];
    const collectionMappings = [];
    if (selectedSourceCollection && selectedTargetCollection) {
      const itemCollectionMappings = [];
      currentMappings.mappings.forEach(m => {
        if (m.type === 'custom_element' || !m.source) { staticMappings.push(m); return; }
        const isSourceIn = m.source.startsWith(selectedSourceCollection.path);
        const isTargetIn = m.target.startsWith(selectedTargetCollection.path);
        if (isSourceIn && isTargetIn) itemCollectionMappings.push(m);
        else staticMappings.push(m);
      });
      const relativeMappings = itemCollectionMappings.map(m => ({
        source: m.source.substring(selectedSourceCollection.path.length + 3),
        target: m.target.substring(selectedTargetCollection.path.length + 3),
        type: m.type
      }));

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
        mappings: relativeMappings
      });
    } else {
      currentMappings.mappings.forEach(m => staticMappings.push(m));
    }
    const dataToSave = {
      rootElement: targetTreeData ? targetTreeData.pathName : "root",
      staticMappings,
      collectionMappings,
    };
    const blob = new Blob([JSON.stringify(dataToSave, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mappings.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // --- Filtering Logic ---
  function filterTree(container, query, isSource = false) {
    const nodes = container.querySelectorAll('.tree-node-item');

    if (!query) {
      // Reset: show everything expanded
      nodes.forEach(n => {
        n.style.display = '';
        n.classList.remove('collapsed');
        const toggle = n.querySelector(':scope > .tree-node .toggle-icon');
        if (toggle) toggle.textContent = '▾';
      });
      // update markers & redraw lines after reset
      updateParentMappingMarkers();
      drawMappings();
      return;
    }

    const lowerQuery = query.toLowerCase();

    nodes.forEach(nodeItem => {
      const label = nodeItem.querySelector('.node-label');
      let searchText = '';

      if (label) {
        if (isSource) {
          // ✅ Only extract schema_id=... content
          const match = label.textContent.match(/\[schema_id=(.*?)\]/i);
          searchText = match ? match[1].toLowerCase() : '';
        } else {
          // ✅ Target tree: only element name (strip schema_id if present)
          searchText = label.textContent.replace(/\[schema_id=.*?\]/gi, '').toLowerCase().trim();
        }
      }

      const isMatch = searchText.includes(lowerQuery);

      if (isMatch) {
        // Show node
        nodeItem.style.display = '';
        nodeItem.classList.remove('collapsed');
        const toggle = nodeItem.querySelector(':scope > .tree-node .toggle-icon');
        if (toggle) toggle.textContent = '▾';

        // Show + expand all parents
        let parent = nodeItem.parentElement;
        while (parent && parent !== container) {
          if (parent.tagName === 'LI') {
            parent.style.display = '';
            parent.classList.remove('collapsed');
            const toggle = parent.querySelector(':scope > .tree-node .toggle-icon');
            if (toggle) toggle.textContent = '▾';
          }
          parent = parent.parentElement;
        }
      } else {
        nodeItem.style.display = 'none';
      }
    });

    // ensure markers and svg lines reflect the filtered state
    updateParentMappingMarkers();
    drawMappings();
  }

  const setupSearch = (inputId, clearBtnId, container, isSource = false) => {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(clearBtnId);
    input.addEventListener('input', () => {
      btn.hidden = !input.value;
      filterTree(container, input.value, isSource);
    });
    btn.addEventListener('click', () => {
      input.value = '';
      btn.hidden = true;
      filterTree(container, '', isSource);
    });
  };

  // ✅ Source tree: match element + schema_id
  setupSearch('sourceSearch', 'clearSourceSearchBtn', sourceTreeContainer, true);

  // ✅ Target tree: match element names only
  setupSearch('targetSearch', 'clearTargetSearchBtn', targetTreeContainer, false);

  window.addEventListener('resize', drawMappings);
  sourceTreeContainer.addEventListener('scroll', drawMappings);
  targetTreeContainer.addEventListener('scroll', drawMappings);
});
