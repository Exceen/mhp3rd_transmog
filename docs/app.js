(function () {
    'use strict';

    // ── Constants ────────────────────────────────────────────────────────────

    const CWCHEAT_BASE = 0x08800000;
    const SLOT_NAMES = ['head', 'chest', 'arms', 'waist', 'legs'];
    const SLOT_LABELS = { head: 'Head', chest: 'Chest', arms: 'Arms', waist: 'Waist', legs: 'Legs' };

    // ── State ────────────────────────────────────────────────────────────────

    let DATA = null;
    let currentMode = 'weapon';
    let outputRaw = '';

    // ── DOM refs ─────────────────────────────────────────────────────────────

    const modePanel = document.getElementById('mode-panel');
    const outputPanel = document.getElementById('output-panel');
    const outputSummary = document.getElementById('output-summary');
    const outputCodes = document.getElementById('output-codes');
    const outputInfo = document.getElementById('output-info');
    const btnCopy = document.getElementById('btn-copy');
    const btnDownload = document.getElementById('btn-download');
    const btnNew = document.getElementById('btn-new');
    const loadingOverlay = document.getElementById('loading-overlay');

    // ── Data Loading ─────────────────────────────────────────────────────────

    async function loadData() {
        try {
            const resp = await fetch('transmog_data.json');
            if (!resp.ok) throw new Error('Failed to load transmog_data.json');
            DATA = await resp.json();
            loadingOverlay.classList.add('hidden');
            initModeTabs();
            renderMode('weapon');
        } catch (err) {
            loadingOverlay.innerHTML = '<p style="color:var(--red)">Failed to load equipment data. Make sure transmog_data.json is in the same folder.</p>';
        }
    }

    // ── Utility ──────────────────────────────────────────────────────────────

    function displayName(names) {
        return names && names.length ? names.join(' / ') : '???';
    }

    function variantLabel(variant, index, setNames) {
        var names = variant.names;
        if (names && names.length) {
            return names[0];
        }
        if (setNames && setNames.length >= 2) {
            return index === 0 ? setNames[0] : setNames[setNames.length - 1];
        }
        return 'Variant ' + (index + 1);
    }

    function hasGenderDiff(targetSet) {
        if (!targetSet || !targetSet.variants) return false;
        return targetSet.variants.some(function (v) { return v.model_m !== v.model_f; });
    }

    function hex(n, width) {
        return (n >>> 0).toString(16).toUpperCase().padStart(width, '0');
    }

    function escapeHtml(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // ── Item Builders ────────────────────────────────────────────────────────

    // Weapon type display order (matches in-game equipment list)
    var WEAPON_TYPE_ORDER = [5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17];

    function getWeaponTypes() {
        var types = [];
        for (var i = 0; i < WEAPON_TYPE_ORDER.length; i++) {
            var tid = String(WEAPON_TYPE_ORDER[i]);
            if (DATA.weapons[tid]) {
                types.push({ typeId: tid, typeName: DATA.weapons[tid].type_name });
            }
        }
        return types;
    }

    function buildWeaponItems(typeId) {
        var wtype = DATA.weapons[typeId];
        if (!wtype) return [];
        var items = [];
        for (var modelStr in wtype.weapons) {
            var w = wtype.weapons[modelStr];
            var names = w.names || ['Model ' + modelStr];
            if (names.length === 1 && (names[0] === 'No Equipment' || names[0] === 'Model 0')) continue;
            items.push({ names: names, model: modelStr, typeId: typeId, entries: w.entries || [] });
        }
        items.sort(function (a, b) { return displayName(a.names).toLowerCase().localeCompare(displayName(b.names).toLowerCase()); });
        return items;
    }

    function buildArmorItems(slot) {
        var sets = DATA.armor[slot].sets;
        var items = sets.filter(function (s) {
            return !(s.names.length === 1 && s.names[0] === 'Nothing Equipped');
        });
        items.sort(function (a, b) {
            return displayName(a.names).toLowerCase().localeCompare(displayName(b.names).toLowerCase());
        });
        return items;
    }

    // ── Code Generation ──────────────────────────────────────────────────────

    // Direct data write approach: writes target model_id directly to weapon data table entries.
    // Each source weapon's entries get the target model_id written to offset +0 (u16).
    // This allows multiple weapon transmogs to be active simultaneously.

    function genWeaponCodes(typeId, sourceWeapon, targetWeapon) {
        var targetModel = parseInt(targetWeapon.model);
        var wtype = DATA.weapons[typeId];
        var tableBase = parseInt(wtype.table_base, 16);
        var entrySize = wtype.entry_size;
        var modelOffset = wtype.model_offset || 0;
        var sourceEntries = sourceWeapon.entries || [];

        var lines = [];
        for (var i = 0; i < sourceEntries.length; i++) {
            var eid = sourceEntries[i];
            var entryAddr = tableBase + eid * entrySize + modelOffset;
            var offset = entryAddr - CWCHEAT_BASE;
            lines.push('_L 0x1' + hex(offset, 7) + ' 0x0000' + hex(targetModel, 4));
        }
        return lines;
    }

    function genArmorCodes(slot, sourceSet, targetSet, forceVariant, swapGender) {
        var tableBase = parseInt(DATA.armor[slot].table_base, 16);
        var entrySize = DATA.armor_entry_size;
        var lines = [];

        var srcVariants = sourceSet.variants;
        var tgtVariants;
        if (targetSet === null) {
            tgtVariants = srcVariants.map(function () { return { model_m: 0, model_f: 0 }; });
        } else {
            tgtVariants = targetSet.variants;
        }

        var pigmentLines = [];

        for (var vi = 0; vi < srcVariants.length; vi++) {
            var srcV = srcVariants[vi];
            var tgtV;
            if (forceVariant !== null && forceVariant !== undefined) {
                tgtV = tgtVariants[forceVariant];
            } else {
                tgtV = vi < tgtVariants.length ? tgtVariants[vi] : tgtVariants[0];
            }
            var targetM = tgtV.model_m;
            var targetF = tgtV.model_f;
            var value;
            if (swapGender) {
                value = ((targetM & 0xFFFF) << 16) | (targetF & 0xFFFF);
            } else {
                value = ((targetF & 0xFFFF) << 16) | (targetM & 0xFFFF);
            }
            value = value >>> 0;

            for (var j = 0; j < srcV.eids.length; j++) {
                var eid = srcV.eids[j];
                var entryAddr = tableBase + eid * entrySize;
                var offset = entryAddr - CWCHEAT_BASE;
                var code = '_L 0x2' + hex(offset, 7) + ' 0x' + hex(value, 8);
                lines.push(code);
                // Enable pigment: write 1 to byte +19 of armor entry
                var pigOffset = (entryAddr + 19) - CWCHEAT_BASE;
                pigmentLines.push('_L 0x0' + hex(pigOffset, 7) + ' 0x00000001');
            }
        }
        return { modelLines: lines, pigmentLines: pigmentLines };
    }

    function genUniversalInvisibleCodes(slot) {
        var tableBase = parseInt(DATA.armor[slot].table_base, 16);
        var entrySize = DATA.armor_entry_size;
        var lines = [];
        var sets = DATA.armor[slot].sets;
        for (var i = 0; i < sets.length; i++) {
            var armorSet = sets[i];
            for (var vi = 0; vi < armorSet.variants.length; vi++) {
                var variant = armorSet.variants[vi];
                if (variant.model_m === 0 && variant.model_f === 0) continue;
                for (var j = 0; j < variant.eids.length; j++) {
                    var eid = variant.eids[j];
                    var entryAddr = tableBase + eid * entrySize;
                    var offset = entryAddr - CWCHEAT_BASE;
                    var code = '_L 0x2' + hex(offset, 7) + ' 0x00000000';
                    lines.push(code);
                }
            }
        }
        return lines;
    }

    function formatCheatBlock(title, lines) {
        return '_C1 ' + title + '\n' + lines.join('\n');
    }

    // ── Output Panel ─────────────────────────────────────────────────────────

    function showOutput(blocks, summary) {
        outputRaw = blocks.join('\n\n');
        outputPanel.classList.remove('hidden');

        var html = '';
        var rawLines = outputRaw.split('\n');
        for (var i = 0; i < rawLines.length; i++) {
            var line = rawLines[i];
            if (line.startsWith('_C')) {
                html += '<span class="line-title">' + escapeHtml(line) + '</span>\n';
            } else if (line.trim() === '') {
                html += '\n';
            } else {
                html += '<span class="line-code">' + escapeHtml(line) + '</span>\n';
            }
        }
        outputCodes.innerHTML = html;

        var totalLines = rawLines.filter(function (l) { return l.startsWith('_L '); }).length;
        outputInfo.textContent = totalLines + ' cheat line' + (totalLines !== 1 ? 's' : '') + ' generated';
        outputSummary.textContent = summary || '';

        outputPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function hideOutput() {
        outputPanel.classList.add('hidden');
        outputRaw = '';
    }

    function copyToClipboard(text, btn) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
                flashCopied(btn);
            });
        } else {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            flashCopied(btn);
        }
    }

    function flashCopied(btn) {
        var orig = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(function () {
            btn.textContent = orig;
            btn.classList.remove('copied');
        }, 1500);
    }

    btnCopy.addEventListener('click', function () {
        copyToClipboard(outputRaw, btnCopy);
    });

    btnDownload.addEventListener('click', function () {
        var blob = new Blob([outputRaw + '\n'], { type: 'text/plain' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'mhp3rd_transmog_codes.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    btnNew.addEventListener('click', function () {
        renderMode(currentMode);
        modePanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    // ── Equipment Selector Component ─────────────────────────────────────────

    function createSelector(container, items, options) {
        options = options || {};
        var allowInvisible = options.allowInvisible || false;
        var presetSearch = options.presetSearch || '';
        var onSelect = options.onSelect || function () {};
        var selected = null;

        var html = '<input type="text" class="search-input" placeholder="Search by name..." value="' + escapeHtml(presetSearch) + '">';
        html += '<div class="item-list"></div>';
        html += '<div class="item-count"></div>';
        html += '<div class="selection-display">Selected: <span class="dim">none</span></div>';
        container.innerHTML = html;

        var searchInput = container.querySelector('.search-input');
        var itemList = container.querySelector('.item-list');
        var itemCount = container.querySelector('.item-count');
        var selectionDisplay = container.querySelector('.selection-display');

        function getItemLabel(item) {
            return displayName(item.names);
        }

        function matchesFilter(item, term) {
            return item.names.some(function (n) { return n.toLowerCase().indexOf(term) !== -1; });
        }

        function renderItems(filter) {
            var filtered;
            if (filter) {
                var term = filter.toLowerCase();
                filtered = items.filter(function (item) {
                    return matchesFilter(item, term);
                });
            } else {
                filtered = items;
            }

            var html = '';
            if (allowInvisible) {
                html += '<div class="item invisible-option" data-index="invisible">** Invisible **</div>';
            }
            if (filtered.length === 0) {
                html += '<div class="no-results">No results found</div>';
            } else {
                for (var i = 0; i < filtered.length; i++) {
                    var item = filtered[i];
                    var isSelected = selected === item;
                    html += '<div class="item' + (isSelected ? ' selected' : '') + '" data-index="' + i + '">' + escapeHtml(getItemLabel(item)) + '</div>';
                }
            }
            itemList.innerHTML = html;
            itemCount.textContent = filtered.length + ' item' + (filtered.length !== 1 ? 's' : '');

            container._filtered = filtered;
        }

        function updateSelectionDisplay() {
            if (container._invisibleSelected) {
                selectionDisplay.innerHTML = 'Selected: <span class="invisible-name">Invisible</span>';
            } else if (selected) {
                selectionDisplay.innerHTML = 'Selected: <span class="selected-name">' + escapeHtml(getItemLabel(selected)) + '</span>';
            } else {
                selectionDisplay.innerHTML = 'Selected: <span class="dim">none</span>';
            }
        }

        itemList.addEventListener('click', function (e) {
            var target = e.target.closest('.item');
            if (!target) return;
            var idx = target.getAttribute('data-index');
            if (idx === 'invisible') {
                selected = null;
                container._invisibleSelected = true;
                onSelect(null);
            } else {
                var i = parseInt(idx);
                selected = container._filtered[i];
                container._invisibleSelected = false;
                onSelect(selected);
            }
            var allItems = itemList.querySelectorAll('.item');
            for (var j = 0; j < allItems.length; j++) {
                allItems[j].classList.remove('selected');
            }
            target.classList.add('selected');
            updateSelectionDisplay();
        });

        var debounceTimer;
        searchInput.addEventListener('input', function () {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(function () {
                renderItems(searchInput.value);
            }, 100);
        });

        renderItems(presetSearch);
        container._invisibleSelected = false;

        return {
            getSelected: function () {
                if (container._invisibleSelected) return null;
                return selected;
            },
            isInvisible: function () {
                return container._invisibleSelected;
            },
            hasSelection: function () {
                return selected !== null || container._invisibleSelected;
            }
        };
    }

    // ── Mode Tab Handling ────────────────────────────────────────────────────

    function initModeTabs() {
        var tabs = document.querySelectorAll('.tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].addEventListener('click', function () {
                var mode = this.getAttribute('data-mode');
                if (mode === currentMode) return;
                for (var j = 0; j < tabs.length; j++) {
                    tabs[j].classList.remove('active');
                }
                this.classList.add('active');
                currentMode = mode;
                hideOutput();
                renderMode(mode);
            });
        }
    }

    function renderMode(mode) {
        modePanel.innerHTML = '';
        hideOutput();
        switch (mode) {
            case 'weapon': renderWeaponMode(); break;
            case 'armor-slot': renderArmorSlotMode(); break;
            case 'armor-set': renderArmorSetMode(); break;
            case 'universal-invisible': renderUniversalInvisibleMode(); break;
        }
    }

    // ── Mode 1: Weapon Transmog ──────────────────────────────────────────────

    function renderWeaponMode() {
        var weaponTypes = getWeaponTypes();

        var typePickerHtml = '<div class="type-picker" id="weapon-type-picker">';
        for (var t = 0; t < weaponTypes.length; t++) {
            typePickerHtml += '<button class="type-btn" data-type="' + weaponTypes[t].typeId + '">' + escapeHtml(weaponTypes[t].typeName) + '</button>';
        }
        typePickerHtml += '</div>';

        modePanel.innerHTML =
            '<div class="section-title">Weapon Transmog</div>' +
            '<p class="hint">Select weapon type, then choose source (equipped) and target (visual).</p>' +
            typePickerHtml +
            '<div id="weapon-content"></div>';

        var picker = document.getElementById('weapon-type-picker');
        picker.addEventListener('click', function (e) {
            var btn = e.target.closest('.type-btn');
            if (!btn) return;
            var allBtns = picker.querySelectorAll('.type-btn');
            for (var j = 0; j < allBtns.length; j++) allBtns[j].classList.remove('active');
            btn.classList.add('active');
            renderWeaponSelectors(btn.getAttribute('data-type'));
        });
    }

    function renderWeaponSelectors(typeId) {
        var items = buildWeaponItems(typeId);
        var typeName = DATA.weapons[typeId].type_name;
        var container = document.getElementById('weapon-content');

        container.innerHTML =
            '<div class="selector-row">' +
                '<div class="selector-col">' +
                    '<div class="selector-label">Source ' + escapeHtml(typeName) + ' (equipped)</div>' +
                    '<div id="weapon-source"></div>' +
                '</div>' +
                '<div class="selector-col">' +
                    '<div class="selector-label">Target ' + escapeHtml(typeName) + ' (visual)</div>' +
                    '<div id="weapon-target"></div>' +
                '</div>' +
            '</div>' +
            '<div class="btn-row">' +
                '<button class="btn btn-primary" id="weapon-generate" disabled>Generate Codes</button>' +
            '</div>';

        var sourceItem = null, targetItem = null;

        function checkReady() {
            document.getElementById('weapon-generate').disabled = !(sourceItem && targetItem);
        }

        createSelector(document.getElementById('weapon-source'), items, {
            onSelect: function (item) { sourceItem = item; checkReady(); }
        });

        createSelector(document.getElementById('weapon-target'), items, {
            onSelect: function (item) { targetItem = item; checkReady(); }
        });

        document.getElementById('weapon-generate').addEventListener('click', function () {
            if (!sourceItem || !targetItem) return;
            var lines = genWeaponCodes(typeId, sourceItem, targetItem);
            var srcLabel = displayName(sourceItem.names);
            var tgtLabel = displayName(targetItem.names);
            var title = 'Weapon Transmog: ' + srcLabel + ' -> ' + tgtLabel;
            var block = formatCheatBlock(title, lines);
            showOutput([block], srcLabel + ' -> ' + tgtLabel);
        });
    }

    // ── Mode 2: Armor (Single Slot) ──────────────────────────────────────────

    function renderArmorSlotMode() {
        modePanel.innerHTML =
            '<div class="section-title">Armor Transmog (Single Slot)</div>' +
            '<p class="hint">Select an armor slot, then choose source and target armor.</p>' +
            '<div class="slot-picker" id="slot-picker"></div>' +
            '<div id="armor-slot-content"></div>';

        renderSlotPicker(document.getElementById('slot-picker'), function (slot) {
            renderSingleSlotFlow(document.getElementById('armor-slot-content'), slot);
        });
    }

    function renderSlotPicker(container, onSelect) {
        var html = '';
        for (var i = 0; i < SLOT_NAMES.length; i++) {
            html += '<button class="slot-btn" data-slot="' + SLOT_NAMES[i] + '">' + SLOT_LABELS[SLOT_NAMES[i]] + '</button>';
        }
        container.innerHTML = html;

        container.addEventListener('click', function (e) {
            var btn = e.target.closest('.slot-btn');
            if (!btn) return;
            var allBtns = container.querySelectorAll('.slot-btn');
            for (var j = 0; j < allBtns.length; j++) allBtns[j].classList.remove('active');
            btn.classList.add('active');
            onSelect(btn.getAttribute('data-slot'));
        });
    }

    function disabledOptionHtml(label) {
        return '<div class="option-group disabled"><div class="option-group-label">' + label + '</div><p class="dim" style="font-size:0.84rem">Select a target armor to configure</p></div>';
    }

    function renderArmorOptions(optContainer, targetItem, isInvisible, state) {
        state.forceVariant = null;
        state.swapGender = false;

        var vHtml = disabledOptionHtml('Variant');
        var gHtml = disabledOptionHtml('Gender');

        if (!isInvisible && targetItem) {
            if (targetItem.variants && targetItem.variants.length >= 2) {
                var setNames = targetItem.names || [];
                var label0 = variantLabel(targetItem.variants[0], 0, setNames);
                var label1 = variantLabel(targetItem.variants[1], 1, setNames);

                vHtml =
                    '<div class="option-group">' +
                        '<div class="option-group-label">Variant</div>' +
                        '<label><input type="radio" name="' + state.radioPrefix + '-variant" value="match" checked> Match armor type <span class="option-detail">(' + escapeHtml(label0) + ' \u2192 ' + escapeHtml(label0) + ', ' + escapeHtml(label1) + ' \u2192 ' + escapeHtml(label1) + ')</span></label>' +
                        '<label><input type="radio" name="' + state.radioPrefix + '-variant" value="0"> ' + escapeHtml(label0) + ' <span class="option-detail">(all pieces)</span></label>' +
                        '<label><input type="radio" name="' + state.radioPrefix + '-variant" value="1"> ' + escapeHtml(label1) + ' <span class="option-detail">(all pieces)</span></label>' +
                    '</div>';
            }

            if (hasGenderDiff(targetItem)) {
                gHtml =
                    '<div class="option-group">' +
                        '<div class="option-group-label">Gender</div>' +
                        '<label><input type="radio" name="' + state.radioPrefix + '-gender" value="default" checked> Default</label>' +
                        '<label><input type="radio" name="' + state.radioPrefix + '-gender" value="swap"> Opposite gender model</label>' +
                    '</div>';
            }
        }

        optContainer.innerHTML = vHtml + gHtml;

        var variantRadios = optContainer.querySelectorAll('input[name="' + state.radioPrefix + '-variant"]');
        for (var i = 0; i < variantRadios.length; i++) {
            variantRadios[i].addEventListener('change', function () {
                if (this.value === 'match') state.forceVariant = null;
                else state.forceVariant = parseInt(this.value);
            });
        }
        var genderRadios = optContainer.querySelectorAll('input[name="' + state.radioPrefix + '-gender"]');
        for (var j = 0; j < genderRadios.length; j++) {
            genderRadios[j].addEventListener('change', function () {
                state.swapGender = this.value === 'swap';
            });
        }
    }

    function renderSingleSlotFlow(container, slot) {
        var items = buildArmorItems(slot);

        container.innerHTML =
            '<div class="selector-row">' +
                '<div class="selector-col">' +
                    '<div class="selector-label">Source ' + SLOT_LABELS[slot] + ' (equipped)</div>' +
                    '<div id="armor-source"></div>' +
                '</div>' +
                '<div class="selector-col">' +
                    '<div class="selector-label">Target ' + SLOT_LABELS[slot] + ' (visual)</div>' +
                    '<div id="armor-target"></div>' +
                '</div>' +
            '</div>' +
            '<div id="armor-options">' +
                disabledOptionHtml('Variant') +
                disabledOptionHtml('Gender') +
            '</div>' +
            '<div class="option-group">' +
                '<label><input type="checkbox" id="armor-pigment"> Enable pigment color</label>' +
            '</div>' +
            '<div class="btn-row">' +
                '<button class="btn btn-primary" id="armor-generate" disabled>Generate Codes</button>' +
            '</div>';

        var sourceItem = null;
        var targetItem = null;
        var isInvisible = false;
        var optState = { forceVariant: null, swapGender: false, radioPrefix: 'armor' };

        function checkReady() {
            document.getElementById('armor-generate').disabled = !(sourceItem && (targetItem || isInvisible));
        }

        createSelector(document.getElementById('armor-source'), items, {
            onSelect: function (item) { sourceItem = item; checkReady(); }
        });

        createSelector(document.getElementById('armor-target'), items, {
            allowInvisible: true,
            onSelect: function (item) {
                if (item === null) {
                    targetItem = null;
                    isInvisible = true;
                } else {
                    targetItem = item;
                    isInvisible = false;
                }
                renderArmorOptions(document.getElementById('armor-options'), targetItem, isInvisible, optState);
                checkReady();
            }
        });

        document.getElementById('armor-generate').addEventListener('click', function () {
            if (!sourceItem) return;
            var target = isInvisible ? null : targetItem;
            var result = genArmorCodes(slot, sourceItem, target, optState.forceVariant, optState.swapGender);
            var includePigment = document.getElementById('armor-pigment').checked;
            var lines = includePigment ? result.modelLines.concat(result.pigmentLines) : result.modelLines;
            var srcName = displayName(sourceItem.names);
            var tgtName = isInvisible ? 'Invisible' : displayName(targetItem.names);
            var suffix = isInvisible ? ' (invisible ' + SLOT_LABELS[slot].toLowerCase() + ')' : '';
            var title = 'Armor Transmog: ' + srcName + ' -> ' + tgtName + suffix;
            var block = formatCheatBlock(title, lines);
            showOutput([block], SLOT_LABELS[slot] + ': ' + srcName + ' -> ' + tgtName);
        });
    }

    // ── Mode 3: Armor (Set) ──────────────────────────────────────────────────

    function renderArmorSetMode() {
        modePanel.innerHTML =
            '<div class="section-title">Armor Transmog (Set)</div>' +
            '<p class="hint">Set persistent search filters, then select source and target for each armor slot.</p>' +
            '<div class="filter-row">' +
                '<div class="filter-col"><label>Source search filter</label><input type="text" id="set-source-filter" placeholder="e.g. Yukumo"></div>' +
                '<div class="filter-col"><label>Target search filter</label><input type="text" id="set-target-filter" placeholder="e.g. Rathalos"></div>' +
            '</div>' +
            '<div class="option-group">' +
                '<label><input type="checkbox" id="set-pigment"> Enable pigment color</label>' +
            '</div>' +
            '<div class="btn-row" style="margin-bottom:16px">' +
                '<button class="btn btn-primary" id="set-start">Start</button>' +
            '</div>' +
            '<div id="set-wizard"></div>';

        document.getElementById('set-start').addEventListener('click', function () {
            var sourceFilter = document.getElementById('set-source-filter').value.trim();
            var targetFilter = document.getElementById('set-target-filter').value.trim();
            this.disabled = true;
            document.getElementById('set-source-filter').disabled = true;
            document.getElementById('set-target-filter').disabled = true;
            var wizard = document.getElementById('set-wizard');
            runArmorSetWizard(wizard, sourceFilter, targetFilter);
            wizard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    }

    function runArmorSetWizard(container, sourceFilter, targetFilter) {
        var results = [];
        var currentSlotIdx = 0;

        function renderStep() {
            if (currentSlotIdx >= SLOT_NAMES.length) {
                finishArmorSet();
                return;
            }
            var slot = SLOT_NAMES[currentSlotIdx];
            var progress = ((currentSlotIdx) / SLOT_NAMES.length * 100);

            container.innerHTML =
                '<div class="wizard-header">' +
                    '<span class="wizard-step-label">Step ' + (currentSlotIdx + 1) + ' of ' + SLOT_NAMES.length + '</span>' +
                    '<div class="wizard-progress"><div class="wizard-progress-fill" style="width:' + progress + '%"></div></div>' +
                '</div>' +
                '<div class="wizard-slot-label">' + SLOT_LABELS[slot] + '</div>' +
                '<div id="wizard-slot-content"></div>' +
                '<div class="btn-row" id="wizard-actions">' +
                    '<button class="btn btn-primary" id="wizard-confirm" disabled>Confirm</button>' +
                    '<button class="btn btn-skip" id="wizard-skip">Skip ' + SLOT_LABELS[slot] + '</button>' +
                '</div>';

            var slotContent = document.getElementById('wizard-slot-content');
            var state = { source: null, target: null, isInvisible: false, forceVariant: null, swapGender: false };
            renderWizardSlotSelectors(slotContent, slot, sourceFilter, targetFilter, state);

            document.getElementById('wizard-skip').addEventListener('click', function () {
                currentSlotIdx++;
                renderStep();
            });

            document.getElementById('wizard-confirm').addEventListener('click', function () {
                if (!state.source) return;
                var target = state.isInvisible ? null : state.target;
                var result = genArmorCodes(slot, state.source, target, state.forceVariant, state.swapGender);
                results.push({
                    slot: slot,
                    modelLines: result.modelLines,
                    pigmentLines: result.pigmentLines,
                    srcName: displayName(state.source.names),
                    tgtName: state.isInvisible ? 'Invisible' : displayName(state.target.names),
                    isInvisible: state.isInvisible
                });
                currentSlotIdx++;
                renderStep();
            });

            slotContent._checkReady = function () {
                document.getElementById('wizard-confirm').disabled = !(state.source && (state.target || state.isInvisible));
            };
        }

        function finishArmorSet() {
            if (results.length === 0) {
                container.innerHTML = '<p class="hint">No codes generated (all slots skipped).</p>';
                return;
            }

            var allModelLines = [];
            var allPigmentLines = [];
            var targetNames = {};
            var sourceNames = {};
            var invisibleSlots = [];

            for (var i = 0; i < results.length; i++) {
                var r = results[i];
                allModelLines = allModelLines.concat(r.modelLines);
                allPigmentLines = allPigmentLines.concat(r.pigmentLines);
                sourceNames[r.srcName] = true;
                if (r.isInvisible) {
                    invisibleSlots.push(SLOT_LABELS[r.slot].toLowerCase());
                } else {
                    targetNames[r.tgtName] = true;
                }
            }

            var includePigment = document.getElementById('set-pigment').checked;
            var allLines = includePigment ? allModelLines.concat(allPigmentLines) : allModelLines;

            var tgtKeys = Object.keys(targetNames);
            var srcKeys = Object.keys(sourceNames);
            var tgtDisplay = tgtKeys.length === 1 ? tgtKeys[0] : (tgtKeys.length === 0 ? 'Invisible' : 'Custom');
            var srcDisplay = srcKeys.length === 1 ? srcKeys[0] : 'Mixed';

            var title = 'Armor Transmog: ' + srcDisplay + ' -> ' + tgtDisplay;
            if (invisibleSlots.length > 0) {
                title += ' (invisible ' + invisibleSlots.join(', ') + ')';
            }

            var block = formatCheatBlock(title, allLines);
            var summary = results.map(function (r) {
                return SLOT_LABELS[r.slot] + ': ' + r.srcName + ' -> ' + r.tgtName;
            }).join('\n');

            container.innerHTML =
                '<div class="wizard-header">' +
                    '<span class="wizard-step-label">Done</span>' +
                    '<div class="wizard-progress"><div class="wizard-progress-fill" style="width:100%"></div></div>' +
                '</div>';

            showOutput([block], summary);
        }

        renderStep();
    }

    function renderWizardSlotSelectors(container, slot, sourceFilter, targetFilter, state) {
        var items = buildArmorItems(slot);
        state.radioPrefix = 'wiz';

        container.innerHTML =
            '<div class="selector-row">' +
                '<div class="selector-col">' +
                    '<div class="selector-label">Source (equipped)</div>' +
                    '<div id="wiz-source"></div>' +
                '</div>' +
                '<div class="selector-col">' +
                    '<div class="selector-label">Target (visual)</div>' +
                    '<div id="wiz-target"></div>' +
                '</div>' +
            '</div>' +
            '<div id="wiz-options">' +
                disabledOptionHtml('Variant') +
                disabledOptionHtml('Gender') +
            '</div>';

        createSelector(document.getElementById('wiz-source'), items, {
            presetSearch: sourceFilter,
            onSelect: function (item) {
                state.source = item;
                if (container._checkReady) container._checkReady();
            }
        });

        createSelector(document.getElementById('wiz-target'), items, {
            allowInvisible: true,
            presetSearch: targetFilter,
            onSelect: function (item) {
                if (item === null) {
                    state.target = null;
                    state.isInvisible = true;
                } else {
                    state.target = item;
                    state.isInvisible = false;
                }
                renderArmorOptions(document.getElementById('wiz-options'), state.target, state.isInvisible, state);
                if (container._checkReady) container._checkReady();
            }
        });
    }

    // ── Mode 4: Universal Invisible ──────────────────────────────────────────

    function renderUniversalInvisibleMode() {
        modePanel.innerHTML =
            '<div class="section-title">Universal Invisible Slot</div>' +
            '<p class="hint">Makes ALL armor in a slot invisible by writing model 0 to every entry. No matter what armor you equip in this slot, it will be invisible.</p>' +
            '<div class="slot-picker" id="invis-slot-picker"></div>' +
            '<div id="invis-output"></div>';

        renderSlotPicker(document.getElementById('invis-slot-picker'), function (slot) {
            var lines = genUniversalInvisibleCodes(slot);
            var title = 'Universal Invisible ' + SLOT_LABELS[slot] + ' (' + lines.length + ' entries)';
            var block = formatCheatBlock(title, lines);
            showOutput([block], SLOT_LABELS[slot] + ': ' + lines.length + ' entries set to invisible');
        });
    }

    // ── Init ─────────────────────────────────────────────────────────────────

    loadData();

})();
