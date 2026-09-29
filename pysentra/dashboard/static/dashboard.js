// PySentra Dashboard Interactivity & Rendering Engine
(function() {
  'use strict';

  let findingsData = [];
  let countsData = {};
  let activeSeverity = 'All';
  let activeScope = 'All';
  let searchQuery = '';
  let activeSort = 'severity-desc';

  const severityWeight = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1
  };

  const severityColors = {
    'Critical': '#EF4444',
    'High': '#F97316',
    'Medium': '#FBBF24',
    'Low': '#10B981',
    'Info': '#38BDF8'
  };

  fetch('/api/findings')
    .then(res => res.json())
    .then(data => {
      findingsData = data.findings || [];
      countsData = data.counts || {};
      initDashboard();
    })
    .catch(err => {
      console.error('Failed to load scan findings:', err);
      const root = document.querySelector('#findings-stream');
      if (root) {
        root.innerHTML = '<div class="empty-state">Failed to load assessment findings from local API.</div>';
      }
    });

  function initDashboard() {
    renderMetricCards();
    renderChart();
    setupControls();
    renderFindings();
  }

  function renderMetricCards() {
    const cardsContainer = document.querySelector('#cards');
    if (!cardsContainer) return;

    const totalCount = Object.values(countsData).reduce((a, b) => a + b, 0);

    let html = `
      <div class="metric-card Total">
        <div class="metric-header">Total Issues</div>
        <div class="metric-value">${totalCount}</div>
      </div>
    `;

    ['Critical', 'High', 'Medium', 'Low', 'Info'].forEach(sev => {
      const count = countsData[sev] || 0;
      html += `
        <div class="metric-card ${sev}">
          <div class="metric-header">${sev}</div>
          <div class="metric-value">${count}</div>
        </div>
      `;
    });

    cardsContainer.innerHTML = html;
  }

  function renderChart() {
    const canvas = document.querySelector('#chart');
    const fallback = document.querySelector('#chart-fallback');
    if (!canvas) return;

    const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const values = labels.map(l => countsData[l] || 0);
    const bgColors = labels.map(l => severityColors[l]);

    const total = values.reduce((a, b) => a + b, 0);

    if (total === 0) {
      if (fallback) {
        fallback.style.display = 'block';
        fallback.textContent = 'No vulnerabilities detected. Clean scan!';
      }
      canvas.style.display = 'none';
      return;
    }

    if (window.Chart) {
      new window.Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: labels,
          datasets: [{
            data: values,
            backgroundColor: bgColors,
            borderColor: '#0F172A',
            borderWidth: 2,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color: '#94A3B8',
                boxWidth: 12,
                padding: 12,
                font: {
                  family: "'Plus Jakarta Sans', sans-serif",
                  size: 11
                }
              }
            }
          },
          cutout: '68%'
        }
      });
    } else {
      if (fallback) {
        fallback.style.display = 'block';
        fallback.innerHTML = labels.map(l => `<span>${l}: ${countsData[l] || 0}</span>`).join(' &nbsp;·&nbsp; ');
      }
      canvas.style.display = 'none';
    }
  }

  function setupControls() {
    // Search input
    const searchInput = document.querySelector('#search');
    const clearBtn = document.querySelector('#clear-search');
    if (searchInput) {
      searchInput.addEventListener('input', e => {
        searchQuery = e.target.value.toLowerCase().trim();
        if (clearBtn) {
          clearBtn.style.display = searchQuery ? 'block' : 'none';
        }
        renderFindings();
      });
    }

    if (clearBtn && searchInput) {
      clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        searchQuery = '';
        clearBtn.style.display = 'none';
        renderFindings();
      });
    }

    // Severity chips
    const chips = document.querySelectorAll('.chip');
    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        chips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        activeSeverity = chip.dataset.severity;
        renderFindings();
      });
    });

    // Scope selector
    const scopeSelect = document.querySelector('#scope-select');
    if (scopeSelect) {
      const scopes = Array.from(new Set(findingsData.map(f => f.scope_area).filter(Boolean))).sort();
      scopeSelect.innerHTML = '<option value="All">All Scopes</option>' + scopes.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
      scopeSelect.addEventListener('change', e => {
        activeScope = e.target.value;
        renderFindings();
      });
    }

    // Sort selector
    const sortSelect = document.querySelector('#sort-select');
    if (sortSelect) {
      sortSelect.addEventListener('change', e => {
        activeSort = e.target.value;
        renderFindings();
      });
    }

    // Expand / Collapse all
    const expandBtn = document.querySelector('#expand-all-btn');
    if (expandBtn) {
      let expanded = false;
      expandBtn.addEventListener('click', () => {
        expanded = !expanded;
        expandBtn.textContent = expanded ? 'Collapse All' : 'Expand All';
        document.querySelectorAll('.poc-details').forEach(d => {
          d.open = expanded;
        });
      });
    }

    // Delegated copy button handlers
    document.addEventListener('click', e => {
      if (e.target && e.target.classList.contains('copy-btn')) {
        const targetId = e.target.dataset.target;
        const codeElement = document.getElementById(targetId);
        if (codeElement) {
          navigator.clipboard.writeText(codeElement.innerText).then(() => {
            const originalText = e.target.innerText;
            e.target.innerText = 'Copied!';
            setTimeout(() => {
              e.target.innerText = originalText;
            }, 1800);
          });
        }
      } else if (e.target && e.target.classList.contains('copy-text-btn')) {
        const textToCopy = e.target.dataset.copy;
        if (textToCopy) {
          navigator.clipboard.writeText(textToCopy).then(() => {
            const originalText = e.target.innerText;
            e.target.innerText = 'Copied!';
            setTimeout(() => {
              e.target.innerText = originalText;
            }, 1800);
          });
        }
      } else if (e.target && e.target.id === 'reset-filters-btn') {
        resetAllFilters();
      }
    });
  }

  function resetAllFilters() {
    activeSeverity = 'All';
    activeScope = 'All';
    searchQuery = '';
    const searchInput = document.querySelector('#search');
    if (searchInput) searchInput.value = '';
    const clearBtn = document.querySelector('#clear-search');
    if (clearBtn) clearBtn.style.display = 'none';
    const chips = document.querySelectorAll('.chip');
    chips.forEach(c => c.classList.toggle('active', c.dataset.severity === 'All'));
    const scopeSelect = document.querySelector('#scope-select');
    if (scopeSelect) scopeSelect.value = 'All';
    renderFindings();
  }

  function renderFindings() {
    const root = document.querySelector('#findings-stream');
    if (!root) return;

    let filtered = findingsData.filter(f => {
      if (activeSeverity !== 'All' && f.severity !== activeSeverity) {
        return false;
      }
      if (activeScope !== 'All' && f.scope_area !== activeScope) {
        return false;
      }
      if (searchQuery) {
        const text = [
          f.title,
          f.description,
          f.remediation,
          f.scope_area,
          f.affected_component,
          f.business_impact,
          f.poc_request,
          f.poc_response_snippet
        ].join(' ').toLowerCase();

        if (!text.includes(searchQuery)) {
          return false;
        }
      }
      return true;
    });

    // Sorting
    filtered.sort((a, b) => {
      if (activeSort === 'severity-desc') {
        return (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0) || (b.cvss_score - a.cvss_score);
      } else if (activeSort === 'severity-asc') {
        return (severityWeight[a.severity] || 0) - (severityWeight[b.severity] || 0) || (a.cvss_score - b.cvss_score);
      } else if (activeSort === 'cvss-desc') {
        return (b.cvss_score - a.cvss_score);
      } else if (activeSort === 'cvss-asc') {
        return (a.cvss_score - b.cvss_score);
      } else if (activeSort === 'title-asc') {
        return a.title.localeCompare(b.title);
      }
      return 0;
    });

    if (filtered.length === 0) {
      root.innerHTML = `
        <div class="empty-state">
          <p>No findings match your current filters.</p>
          <button id="reset-filters-btn" class="btn btn-secondary" style="margin-top:14px;">Reset Filters</button>
        </div>
      `;
      return;
    }

    let html = '';
    filtered.forEach((f, idx) => {
      const reqId = `poc-req-${idx}`;
      const resId = `poc-res-${idx}`;

      const stepsHtml = (f.steps_to_reproduce && f.steps_to_reproduce.length > 0)
        ? `<div class="steps-wrapper" style="margin-top:10px;">
             <div class="poc-block-title">Reproduction Steps</div>
             <ol class="steps-list">${f.steps_to_reproduce.map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ol>
           </div>`
        : '';

      const reqBlock = f.poc_request ? `
        <div>
          <div class="poc-block-title">
            <span>PoC Request</span>
            <button class="copy-btn" data-target="${reqId}">Copy</button>
          </div>
          <pre class="code-block" id="${reqId}">${escapeHtml(f.poc_request)}</pre>
        </div>
      ` : '';

      const resBlock = f.poc_response_snippet ? `
        <div>
          <div class="poc-block-title">
            <span>Raw Response Evidence</span>
            <button class="copy-btn" data-target="${resId}">Copy</button>
          </div>
          <pre class="code-block" id="${resId}">${escapeHtml(f.poc_response_snippet)}</pre>
        </div>
      ` : '';

      html += `
        <article class="finding-card ${escapeHtml(f.severity)}">
          <div class="finding-top">
            <div class="finding-title-group">
              <span class="sev-badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
              <h2 class="finding-title">${escapeHtml(f.title)}</h2>
            </div>
            <div class="cvss-score-chip">CVSS ${Number(f.cvss_score).toFixed(1)}</div>
          </div>

          <div class="meta-tags">
            <span class="meta-item"><b>Scope:</b> ${escapeHtml(f.scope_area)}</span>
            <span class="meta-item"><b>Component:</b> <span class="mono">${escapeHtml(f.affected_component || 'Target Domain')}</span>
              ${f.affected_component ? `<button class="copy-text-btn" data-copy="${escapeHtml(f.affected_component)}" title="Copy component path">Copy</button>` : ''}
            </span>
          </div>

          <p class="finding-desc">${escapeHtml(f.description)}</p>

          <div class="remediation-box">
            <b>Remediation:</b> ${escapeHtml(f.remediation)}
          </div>

          <details class="poc-details">
            <summary>
              <span>Evidence & Proof-of-Concept</span>
              <span class="mono" style="font-size:11px; opacity:0.8;">Click to view raw payload & response</span>
            </summary>
            <div class="poc-content">
              ${reqBlock}
              ${resBlock}
              ${stepsHtml}
            </div>
          </details>
        </article>
      `;
    });

    root.innerHTML = html;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
})();
