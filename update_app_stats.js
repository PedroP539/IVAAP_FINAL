const fs = require('fs');
const path = '/Users/pedropina/Desktop/TESTE/IVAAP_2 copy/IVAAP_FINAL/app.js';
let content = fs.readFileSync(path, 'binary');

const metricsCode = `
        const newMetricsQueries = await Promise.all([
            dbGet('SELECT * FROM images WHERE status = "pending" ORDER BY approvals DESC, uploaded_at ASC LIMIT 1'),
            dbGet('SELECT * FROM images WHERE status = "pending" ORDER BY rejections DESC, uploaded_at ASC LIMIT 1'),
            dbGet('SELECT * FROM images WHERE uploaded_by = ? ORDER BY approvals DESC, uploaded_at ASC LIMIT 1', [req.user.username]),
            dbGet('SELECT * FROM images WHERE uploaded_by = ? ORDER BY rejections DESC, uploaded_at ASC LIMIT 1', [req.user.username])
        ]);
        const newMetrics = {
            globalPendingVoted: newMetricsQueries[0] || null,
            globalPendingRejected: newMetricsQueries[1] || null,
            userMostVoted: newMetricsQueries[2] || null,
            userMostRejected: newMetricsQueries[3] || null
        };
`;

// Insert new metrics
if (!content.includes('const newMetrics = {')) {
    content = content.replace(
        'const globalPendingCount = globalLatestQueries[3]?.count || 0;',
        'const globalPendingCount = globalLatestQueries[3]?.count || 0;\n' + metricsCode
    );
}

// Remove star queries
content = content.replace(
    /dbGet\('SELECT \* FROM images WHERE rating_count > 0 ORDER BY rating_count DESC, avg_rating DESC, uploaded_at DESC LIMIT 1'\),\s*dbGet\('SELECT \* FROM images WHERE rating_count > 0 ORDER BY rating_count ASC, uploaded_at DESC LIMIT 1'\)/,
    ''
);

// Clean up array comma if needed (the regex above removes the items but there might be a trailing comma or the array close brackets adjustment)
// Actually the regex included matches for clean deletion? No, I just matched the queries.
// The code had: globalQueries = await Promise.all([ ... queried ... ]);
// Re-check regex: I matched the strings.
// I should check if I left a dangling comma or syntax error.
// The original ended with `LIMIT 1')\n            ]);`
// My replace leaves `            ]);` effectively empty items? No, I replaced them with empty string.
// So `LIMIT 1'),\n            ]);` -> `LIMIT 1 (prev query)'),\n            ]);`
// I need to be careful with commas.
// Better: Regex match the preceding comma?
// `LIMIT 1'),\n                dbGet...`
// I'll assume the previous query has logic handling.
// Let's refine the replacement.
// Match `,` before the star queries.
content = content.replace(
    /,\s*dbGet\('SELECT \* FROM images WHERE rating_count > 0 ORDER BY rating_count DESC, avg_rating DESC, uploaded_at DESC LIMIT 1'\),\s*dbGet\('SELECT \* FROM images WHERE rating_count > 0 ORDER BY rating_count ASC, uploaded_at DESC LIMIT 1'\)/,
    ''
);

// Remove globalStats properties
content = content.replace(/topRated: globalQueries\[8\] \|\| null,\s*leastRated: globalQueries\[9\] \|\| null/s, '');

// Update res.render calls - add newMetrics
// Avoid double adding if ran twice
if (!content.includes('newMetrics,')) {
    content = content.replace(/userActivity,/g, 'userActivity, newMetrics,');
}

// Remove explicit nulls in user render
content = content.replace(/topRated: null,\s*leastRated: null/s, '');

fs.writeFileSync(path, content, 'binary');
console.log('app.js updated');
