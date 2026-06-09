import re

with open('/Users/GLA3/Documents/实验/claude/agentic-pentest/WEBUI.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Update title
html = html.replace('大模型思维链 (Agent Thoughts)', '任务执行流 (Execution Tree)')

# 2. Add mermaid js
html = html.replace('</head>', '    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>\n    <script>mermaid.initialize({ startOnLoad: false, theme: \'dark\' });</script>\n</head>')

# 3. Update poll function
html = html.replace('const [progress, payloads, tasks, logsRes] = await Promise.all([', 
                    'const [progress, payloads, tasks, logsRes, allTasksRes] = await Promise.all([')
html = html.replace("apiFetch('/llm_logs').catch(() => ({ logs: [] }))",
                    "apiFetch('/llm_logs').catch(() => ({ logs: [] })),\n                    apiFetch('/tasks/all').catch(() => ({ tasks: [] }))")
html = html.replace('updateDashboard(progress, payloads, tasks, logsRes);',
                    'updateDashboard(progress, payloads, tasks, logsRes, allTasksRes);')

# 4. Update updateDashboard
html = html.replace('function updateDashboard(prog, payloads, footprintsData, logsRes) {',
                    'function updateDashboard(prog, payloads, footprintsData, logsRes, allTasksRes) {')
html = html.replace('renderLLMLogs(logsRes.logs || []);', 'renderTaskTree(allTasksRes.tasks || []);')

# 5. Add renderTaskTree and helper
append_js = """
        let lastTreeHash = '';
        function hashCode(s) {
            return s.split('').reduce((a,b)=>{a=((a<<5)-a)+b.charCodeAt(0);return a&a},0);
        }

        async function renderTaskTree(tasks) {
            const list = document.getElementById('logList');
            setText('logCount', tasks.length);

            if (!tasks.length) {
                list.innerHTML = '<div class="empty-state">暂无任务数据...</div>';
                return;
            }

            let mmd = "graph LR\\n";
            mmd += "  ROOT((🚀 目标扫描)):::rootClass\\n";
            
            const targets = {};
            
            tasks.forEach(t => {
                const target = t.target || "Unknown";
                const parts = target.split(":");
                const ip = parts[0];
                const port = parts.length > 1 ? parts[1] : null;
                
                if (!targets[ip]) targets[ip] = { ports: {}, no_port: [] };
                
                if (port) {
                    if (!targets[ip].ports[port]) targets[ip].ports[port] = [];
                    targets[ip].ports[port].push(t);
                } else {
                    targets[ip].no_port.push(t);
                }
            });

            Object.keys(targets).forEach(ip => {
                const ipNode = "IP_" + ip.replace(/\\./g, "_");
                mmd += `  ROOT --> ${ipNode}["🎯 ${ip}"]:::ipClass\\n`;
                
                const targetData = targets[ip];
                
                targetData.no_port.forEach(t => {
                    const tNode = "T_" + t.id.replace(/-/g, "_");
                    let statusIcon = t.status === "DONE" ? "✅" : (t.status === "FAILED" ? "❌" : "⏳");
                    mmd += `  ${ipNode} --> ${tNode}["${statusIcon} ${t.tool}"]:::${t.status.toLowerCase()}Class\\n`;
                });
                
                Object.keys(targetData.ports).forEach(port => {
                    const portNode = ipNode + "_PORT_" + port;
                    mmd += `  ${ipNode} --> ${portNode}["🔌 Port ${port}"]:::portClass\\n`;
                    
                    targetData.ports[port].forEach(t => {
                        const tNode = "T_" + t.id.replace(/-/g, "_");
                        let statusIcon = t.status === "DONE" ? "✅" : (t.status === "FAILED" ? "❌" : "⏳");
                        mmd += `  ${portNode} --> ${tNode}["${statusIcon} ${t.tool}"]:::${t.status.toLowerCase()}Class\\n`;
                    });
                });
            });

            mmd += `
            classDef rootClass fill:#ff5722,color:#fff,stroke:#bf360c,stroke-width:2px;
            classDef ipClass fill:#1e88e5,color:#fff,stroke:#0d47a1,stroke-width:2px;
            classDef portClass fill:#00897b,color:#fff,stroke:#004d40,stroke-width:2px;
            classDef doneClass fill:#43a047,color:#fff,stroke:#1b5e20,stroke-width:1px;
            classDef failedClass fill:#e53935,color:#fff,stroke:#b71c1c,stroke-width:1px;
            classDef pendingClass fill:#fb8c00,color:#fff,stroke:#e65100,stroke-width:1px;
            classDef runningClass fill:#8e24aa,color:#fff,stroke:#4a148c,stroke-width:1px;
            `;

            const currentHash = String(hashCode(mmd));
            if (lastTreeHash === currentHash) {
                return;
            }
            lastTreeHash = currentHash;

            try {
                const { svg } = await mermaid.render('mermaid-tree-' + Date.now(), mmd);
                list.innerHTML = `<div class="mermaid-container" style="overflow-x: auto; overflow-y: hidden; height:100%; display:flex; align-items:flex-start;">${svg}</div>`;
            } catch (err) {
                console.error("Mermaid render error:", err);
            }
        }
"""

html = html.replace('function escapeHTML(str) {', append_js + '\n        function escapeHTML(str) {')

with open('/Users/GLA3/Documents/实验/claude/agentic-pentest/WEBUI.html', 'w', encoding='utf-8') as f:
    f.write(html)
