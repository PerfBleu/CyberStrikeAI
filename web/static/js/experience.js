// 全局渗透经验库管理

function expT(key, opts) {
    if (typeof window.t === 'function') return window.t(key, opts);
    return key;
}

let experienceList = [];
let experiencePagination = { currentPage: 1, pageSize: 20, total: 0 };
let experienceSaving = false;
let experienceEnabled = true;

function getExperienceNotEnabledHTML() {
    return `
        <div class="empty-state" style="text-align:center;padding:48px 24px;">
            <h3 style="margin-bottom:10px;color:#666;">${expT('experience.notEnabledTitle')}</h3>
            <p style="color:#999;margin-bottom:20px;">${expT('experience.notEnabledHint')}</p>
            <button onclick="openExperienceSettings()" style="padding:8px 16px;border-radius:6px;border:none;background:#2563eb;color:#fff;cursor:pointer;">
                ${expT('experience.goToSettings')}
            </button>
        </div>`;
}

async function loadExperienceStats() {
    const bar = document.getElementById('experience-stats');
    if (!bar) return;
    try {
        const res = await apiFetch('/api/experiences/stats');
        if (res.status === 503) {
            experienceEnabled = false;
            return;
        }
        if (!res.ok) return;
        const data = await res.json();
        experienceEnabled = true;
        const totalEl = bar.querySelector('[data-stat="total"]');
        const indexedEl = bar.querySelector('[data-stat="indexed"]');
        const confirmedEl = bar.querySelector('[data-stat="confirmed"]');
        if (totalEl) totalEl.textContent = data.total ?? '-';
        if (indexedEl) indexedEl.textContent = data.indexed ?? '-';
        if (confirmedEl) confirmedEl.textContent = (data.by_confidence && data.by_confidence.confirmed) || 0;
    } catch (e) {
        console.warn('loadExperienceStats', e);
    }
}

async function loadExperiences(page) {
    page = page || experiencePagination.currentPage || 1;
    experiencePagination.currentPage = page;
    const container = document.getElementById('experience-items-list');
    if (!container) return;

    const limit = experiencePagination.pageSize;
    const offset = (page - 1) * limit;
    const q = (document.getElementById('experience-search') || {}).value || '';
    const vulnType = (document.getElementById('experience-vuln-type-filter') || {}).value || '';
    const targetClass = (document.getElementById('experience-target-class-filter') || {}).value || '';
    const confidence = (document.getElementById('experience-confidence-filter') || {}).value || '';

    let url = `/api/experiences?limit=${limit}&offset=${offset}`;
    if (q.trim()) url += '&q=' + encodeURIComponent(q.trim());
    if (vulnType.trim()) url += '&vuln_type=' + encodeURIComponent(vulnType.trim());
    if (targetClass.trim()) url += '&target_class=' + encodeURIComponent(targetClass.trim());
    if (confidence.trim()) url += '&confidence=' + encodeURIComponent(confidence.trim());

    try {
        const res = await apiFetch(url);
        if (res.status === 503) {
            experienceEnabled = false;
            container.innerHTML = getExperienceNotEnabledHTML();
            return;
        }
        if (!res.ok) {
            container.innerHTML = `<div class="error-msg">${expT('experience.loadFailed')}</div>`;
            return;
        }
        const data = await res.json();
        experienceEnabled = true;
        experienceList = data.experiences || [];
        experiencePagination.total = data.total || 0;
        renderExperienceList(experienceList);
        renderExperiencePagination();
        await loadExperienceStats();
    } catch (e) {
        console.error(e);
        container.innerHTML = `<div class="error-msg">${expT('experience.loadFailed')}</div>`;
    }
}

function renderExperienceList(items) {
    const container = document.getElementById('experience-items-list');
    if (!container) return;
    if (!items || items.length === 0) {
        container.innerHTML = `<div class="empty-state">${expT('experience.empty')}</div>`;
        return;
    }
    let html = '<div class="knowledge-items-grid">';
    items.forEach(function (item) {
        const preview = [item.detection_hints, item.fingerprint, item.exploit_pattern]
            .map(function (s) { return (s || '').trim(); })
            .find(function (s) { return s; }) || '';
        const previewText = preview.length > 160 ? preview.slice(0, 160) + '…' : preview;
        html += `
        <div class="knowledge-item-card" data-id="${escapeHtml(item.id)}">
            <div class="knowledge-item-card-header">
                <div class="knowledge-item-card-title-row">
                    <h4 class="knowledge-item-card-title" title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</h4>
                    <div class="knowledge-item-card-actions">
                        <button class="knowledge-item-action-btn" data-require-permission="experience:write" onclick="editExperienceItem('${item.id}')" title="${expT('common.edit')}">✎</button>
                        <button class="knowledge-item-action-btn knowledge-item-delete-btn" data-require-permission="experience:delete" onclick="deleteExperienceItem('${item.id}')" title="${expT('common.delete')}">🗑</button>
                    </div>
                </div>
                <div class="knowledge-item-path">${escapeHtml(item.vuln_type || '-')} · ${escapeHtml(item.target_class || '-')} · <span class="confidence-${escapeHtml(item.confidence)}">${escapeHtml(item.confidence)}</span></div>
            </div>
            <div class="knowledge-item-card-content">
                <p class="knowledge-item-preview">${escapeHtml(previewText)}</p>
            </div>
        </div>`;
    });
    html += '</div>';
    container.innerHTML = html;
    if (typeof applyRBACToUI === 'function') applyRBACToUI(container);
}

function renderExperiencePagination() {
    const container = document.getElementById('experience-pagination');
    if (!container) return;
    const { currentPage, pageSize, total } = experiencePagination;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    let html = '<div class="knowledge-pagination" style="display:flex;justify-content:center;gap:8px;padding:16px;">';
    html += `<button class="pagination-btn" onclick="loadExperiences(${currentPage - 1})" ${currentPage <= 1 ? 'disabled' : ''}>${expT('common.prevPage')}</button>`;
    html += `<span style="padding:0 12px;">${currentPage} / ${totalPages} (${total})</span>`;
    html += `<button class="pagination-btn" onclick="loadExperiences(${currentPage + 1})" ${currentPage >= totalPages ? 'disabled' : ''}>${expT('common.nextPage')}</button>`;
    html += '</div>';
    container.innerHTML = html;
}

let experienceSearchTimeout = null;
function handleExperienceSearchInput() {
    clearTimeout(experienceSearchTimeout);
    experienceSearchTimeout = setTimeout(function () {
        loadExperiences(1);
    }, 350);
}

function showAddExperienceModal() {
    if (typeof requirePermission === 'function' && !requirePermission('experience:write')) return;
    document.getElementById('experience-item-modal-title').textContent = expT('experience.add');
    document.getElementById('experience-item-id').value = '';
    document.getElementById('experience-item-title').value = '';
    document.getElementById('experience-item-vuln-type').value = '';
    document.getElementById('experience-item-target-class').value = '';
    document.getElementById('experience-item-confidence').value = 'tentative';
    document.getElementById('experience-item-tags').value = '';
    document.getElementById('experience-item-fingerprint').value = '';
    document.getElementById('experience-item-detection-hints').value = '';
    document.getElementById('experience-item-exploit-pattern').value = '';
    document.getElementById('experience-item-modal').style.display = 'flex';
}

async function editExperienceItem(id) {
    if (typeof requirePermission === 'function' && !requirePermission('experience:write')) return;
    try {
        const res = await apiFetch('/api/experiences/' + encodeURIComponent(id));
        if (!res.ok) throw new Error('load failed');
        const item = await res.json();
        document.getElementById('experience-item-modal-title').textContent = expT('experience.edit');
        document.getElementById('experience-item-id').value = item.id;
        document.getElementById('experience-item-title').value = item.title || '';
        document.getElementById('experience-item-vuln-type').value = item.vuln_type || '';
        document.getElementById('experience-item-target-class').value = item.target_class || '';
        document.getElementById('experience-item-confidence').value = item.confidence || 'tentative';
        document.getElementById('experience-item-tags').value = item.tags || '';
        document.getElementById('experience-item-fingerprint').value = item.fingerprint || '';
        document.getElementById('experience-item-detection-hints').value = item.detection_hints || '';
        document.getElementById('experience-item-exploit-pattern').value = item.exploit_pattern || '';
        document.getElementById('experience-item-modal').style.display = 'flex';
    } catch (e) {
        alert(expT('experience.loadFailed'));
    }
}

function closeExperienceModal() {
    const m = document.getElementById('experience-item-modal');
    if (m) m.style.display = 'none';
}

async function saveExperienceItem() {
    if (experienceSaving) return;
    if (typeof requirePermission === 'function' && !requirePermission('experience:write')) return;
    const id = (document.getElementById('experience-item-id') || {}).value || '';
    const payload = {
        title: (document.getElementById('experience-item-title') || {}).value.trim(),
        vuln_type: (document.getElementById('experience-item-vuln-type') || {}).value.trim(),
        target_class: (document.getElementById('experience-item-target-class') || {}).value.trim(),
        confidence: (document.getElementById('experience-item-confidence') || {}).value || 'tentative',
        tags: (document.getElementById('experience-item-tags') || {}).value.trim(),
        fingerprint: (document.getElementById('experience-item-fingerprint') || {}).value.trim(),
        detection_hints: (document.getElementById('experience-item-detection-hints') || {}).value.trim(),
        exploit_pattern: (document.getElementById('experience-item-exploit-pattern') || {}).value.trim()
    };
    if (!payload.title) {
        alert(expT('experience.titleRequired'));
        return;
    }
    experienceSaving = true;
    try {
        const url = id ? '/api/experiences/' + encodeURIComponent(id) : '/api/experiences';
        const method = id ? 'PUT' : 'POST';
        const res = await apiFetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok) throw new Error(data.error || expT('experience.saveFailed'));
        closeExperienceModal();
        await loadExperiences(experiencePagination.currentPage);
    } catch (e) {
        alert(e.message || expT('experience.saveFailed'));
    } finally {
        experienceSaving = false;
    }
}

async function deleteExperienceItem(id) {
    if (typeof requirePermission === 'function' && !requirePermission('experience:delete')) return;
    if (!confirm(expT('experience.deleteConfirm'))) return;
    try {
        const res = await apiFetch('/api/experiences/' + encodeURIComponent(id), { method: 'DELETE' });
        if (!res.ok) {
            const data = await res.json().catch(function () { return {}; });
            throw new Error(data.error || 'delete failed');
        }
        await loadExperiences(experiencePagination.currentPage);
    } catch (e) {
        alert(e.message || expT('experience.deleteFailed'));
    }
}

async function reindexAllExperiences() {
    if (typeof requirePermission === 'function' && !requirePermission('experience:write')) return;
    if (!confirm(expT('experience.reindexAllConfirm'))) return;
    try {
        const res = await apiFetch('/api/experiences/reindex', { method: 'POST' });
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok) throw new Error(data.error || 'reindex failed');
        alert(expT('experience.reindexAllDone', { indexed: data.indexed || 0, failed: data.failed || 0 }));
        await loadExperienceStats();
    } catch (e) {
        alert(e.message || expT('experience.reindexFailed'));
    }
}

async function runExperienceSemanticSearch() {
    const q = ((document.getElementById('experience-semantic-query') || {}).value || '').trim();
    if (!q) return;
    const box = document.getElementById('experience-semantic-results');
    if (box) box.innerHTML = '<div class="loading-spinner">' + expT('common.loading') + '</div>';
    try {
        const res = await apiFetch('/api/experiences/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                query: q,
                vuln_type: (document.getElementById('experience-vuln-type-filter') || {}).value.trim(),
                target_class: (document.getElementById('experience-target-class-filter') || {}).value.trim(),
                top_k: 5
            })
        });
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok) throw new Error(data.error || 'search failed');
        if (!box) return;
        const results = data.results || [];
        if (results.length === 0) {
            box.innerHTML = '<div class="empty-state">' + expT('experience.searchEmpty') + '</div>';
            return;
        }
        let html = '<div class="experience-semantic-results-list">';
        results.forEach(function (r, i) {
            const exp = r.experience || r.Experience || {};
            const sim = (r.similarity != null ? r.similarity : r.Score) || 0;
            html += `<div class="experience-search-hit"><strong>${i + 1}. ${escapeHtml(exp.title || '')}</strong> (${(sim * 100).toFixed(1)}%)<br>` +
                `<span class="muted">${escapeHtml(exp.vuln_type || '')} · ${escapeHtml(exp.target_class || '')}</span></div>`;
        });
        html += '</div>';
        box.innerHTML = html;
    } catch (e) {
        if (box) box.innerHTML = '<div class="error-msg">' + escapeHtml(e.message) + '</div>';
    }
}

function initExperiencePage() {
    loadExperiences(1);
}

if (typeof switchPage === 'function') {
    const _origSwitchPage = switchPage;
    window.switchPage = function (page) {
        _origSwitchPage(page);
        if (page === 'experience-management' && typeof initExperiencePage === 'function') {
            initExperiencePage();
        }
    };
}

function openExperienceSettings() {
    if (typeof switchPage === 'function') switchPage('settings');
    setTimeout(function () {
        if (typeof switchSettingsSection === 'function') {
            switchSettingsSection('experience');
        }
    }, 100);
}
