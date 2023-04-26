const nodemailer = require('nodemailer')
// const { google } = require('googleapis')
// const OAuth2 = google.auth.OAuth2

// const OAuth2_client = new OAuth2(, process.env.JWT_ACCESS_SECRET)

class MailService {

    constructor() {
        // this.transporter = nodemailer.createTransport({
        //     host: process.env.SMTP_HOST,
        //     port: process.env.SMTP_PORT,
        //     secure: true,
        //     auth: {
        //         user: process.env.SMTP_USER, 
        //         pass: process.env.SMTP_PASSWORD
        //     }, 
        // })

        this.transporter = nodemailer.createTransport({
            service: 'gmail', 
            auth: {
                user: process.env.SMTP_USER, 
                pass: process.env.SMTP_PASSWORD
            }
        });
    }

    async sendActivationMail(to, link) {
        await this.transporter.sendMail({
            from: process.env.SMTP_USER,
            to,
            subject: 'Активация аккаунта на ' + process.env.API_URL,
            text: '',
            html: 
            `
                <div>
                    <h1>Для активации перейдите по ссылке</h1>
                    <a href="${link}">${link}</a>
                </div>
            ` 
        }, function(error, info) {
            if(error) {
                console.log(error)
            } else {
                console.log("Email sent")
            }
        }) 
    }
}

module.exports = new MailService()