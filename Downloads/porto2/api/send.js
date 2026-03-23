export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const { name, email, subject, message } = req.body;

    const html = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0f;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <tr>
          <td style="background:linear-gradient(135deg,#6c63ff,#00d4ff);border-radius:20px 20px 0 0;padding:40px;text-align:center;">
            <p style="margin:0 0 10px;font-size:13px;color:rgba(255,255,255,0.8);letter-spacing:3px;text-transform:uppercase;">Portfolio</p>
            <h1 style="margin:0;font-size:30px;font-weight:900;color:#ffffff;">&lt;MH/&gt;</h1>
            <p style="margin:15px 0 0;font-size:16px;color:rgba(255,255,255,0.9);">Nouveau message recu ✉️</p>
          </td>
        </tr>

        <tr>
          <td style="background:#12121a;padding:40px;border-left:1px solid rgba(108,99,255,0.2);border-right:1px solid rgba(108,99,255,0.2);">
            <p style="margin:0 0 30px;font-size:15px;color:#b0b0c0;line-height:1.6;">Salut Israel 👋, tu as recu un nouveau message depuis ton portfolio !</p>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:15px;">
              <tr><td style="padding:15px 20px;background:#16162a;border-radius:12px;border-left:4px solid #6c63ff;">
                <p style="margin:0 0 4px;font-size:11px;color:#6a6a80;text-transform:uppercase;letter-spacing:1px;">Nom</p>
                <p style="margin:0;font-size:16px;font-weight:700;color:#ffffff;">${name}</p>
              </td></tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:15px;">
              <tr><td style="padding:15px 20px;background:#16162a;border-radius:12px;border-left:4px solid #00d4ff;">
                <p style="margin:0 0 4px;font-size:11px;color:#6a6a80;text-transform:uppercase;letter-spacing:1px;">Email</p>
                <p style="margin:0;font-size:16px;font-weight:700;color:#00d4ff;">${email}</p>
              </td></tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:25px;">
              <tr><td style="padding:15px 20px;background:#16162a;border-radius:12px;border-left:4px solid #ff6b6b;">
                <p style="margin:0 0 4px;font-size:11px;color:#6a6a80;text-transform:uppercase;letter-spacing:1px;">Sujet</p>
                <p style="margin:0;font-size:16px;font-weight:700;color:#ffffff;">${subject}</p>
              </td></tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:30px;">
              <tr><td style="padding:20px;background:#1a1a2e;border-radius:12px;border:1px solid rgba(108,99,255,0.2);">
                <p style="margin:0 0 10px;font-size:11px;color:#6a6a80;text-transform:uppercase;letter-spacing:1px;">Message</p>
                <p style="margin:0;font-size:15px;color:#b0b0c0;line-height:1.8;">${message}</p>
              </td></tr>
            </table>

            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td align="center">
                <a href="mailto:${email}?subject=Re: ${subject}" style="display:inline-block;padding:14px 40px;background:linear-gradient(135deg,#6c63ff,#00d4ff);color:#ffffff;font-size:15px;font-weight:700;text-decoration:none;border-radius:50px;">
                  Repondre a ${name} →
                </a>
              </td></tr>
            </table>
          </td>
        </tr>

        <tr>
          <td style="background:#0a0a0f;border:1px solid rgba(108,99,255,0.2);border-top:none;border-radius:0 0 20px 20px;padding:25px 40px;text-align:center;">
            <p style="margin:0 0 5px;font-size:13px;color:#6a6a80;">Israel HOLOGAN · Developpeur Full Stack</p>
            <p style="margin:0;font-size:12px;color:#3a3a50;">Cotonou, Benin · michaelhologan45@gmail.com</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            from: 'Portfolio <onboarding@resend.dev>',
            to: 'michaelhologan45@gmail.com',
            subject: `[Portfolio] ${subject}`,
            html: html
        })
    });

    const data = await response.json();
    res.status(200).json(data);
}
