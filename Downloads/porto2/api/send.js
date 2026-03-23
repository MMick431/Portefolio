export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const { name, email, subject, message } = req.body;

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
            html: `
                <h3>Nouveau message de ${name}</h3>
                <p><b>Email:</b> ${email}</p>
                <p><b>Sujet:</b> ${subject}</p>
                <p><b>Message:</b> ${message}</p>
            `
        })
    });

    const data = await response.json();
    res.status(200).json(data);
}