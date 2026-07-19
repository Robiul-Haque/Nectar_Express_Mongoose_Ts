const nodemailer = require('nodemailer');

const [, , status, repo, sha, actor, serverUrl, runId] = process.argv;

if (!status) {
    console.error('Usage: node send-email.js <success|failed> [repo] [sha] [actor] [server_url] [run_id]');
    process.exit(1);
}

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_TO } = process.env;

if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASSWORD || !EMAIL_TO) {
    console.error('Missing required SMTP environment variables');
    process.exit(1);
}

const isSuccess = status === 'success';

const subject = isSuccess ? '✅ Nectar Backend Deployment Successful' : '❌ Nectar Backend Deployment Failed';

const runUrl = `${serverUrl}/${repo}/actions/runs/${runId}`;

const html = `
<h2>${isSuccess ? '✅ Deployment Successful' : '❌ Deployment Failed'}</h2>

<p><strong>Repository:</strong> ${repo}</p>

<p><strong>Commit:</strong></p>
<code>${sha}</code>

<p><strong>Triggered By:</strong> ${actor}</p>

<p><a href="${runUrl}">View GitHub Action</a></p>
`;

const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: {
        user: SMTP_USER,
        pass: SMTP_PASSWORD,
    },
});

(async () => {
    try {
        await transporter.sendMail({
            from: `"GitHub Actions" <${SMTP_USER}>`,
            to: EMAIL_TO,
            subject,
            html,
        });

        console.log("✅ Email sent.");
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
})();