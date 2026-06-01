using MailKit.Net.Smtp;
using MimeKit;
using MimeKit.Text;
using System.Threading.Tasks;

namespace Websegura.Services
{
    public class EmailSender : IEmailSender
    {
        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var mimeMessage = new MimeMessage();
            mimeMessage.From.Add(new MailboxAddress("WebSegura Auth", "vanegasjorge731@gmail.com"));
            mimeMessage.To.Add(MailboxAddress.Parse(email));
            mimeMessage.Subject = subject;
            mimeMessage.Body = new TextPart(TextFormat.Html) { Text = message };

            using var client = new SmtpClient();
            try
            {
                // Conectar al servidor SMTP de Gmail
                await client.ConnectAsync("smtp.gmail.com", 587, MailKit.Security.SecureSocketOptions.StartTls);

                // Autenticar con tu correo y contraseña de aplicación de 16 letras
                await client.AuthenticateAsync("vanegasjorge731@gmail.com", "fibutuulmraaaqbb");

                // Enviar el correo
                await client.SendAsync(mimeMessage);
            }
            catch (System.Exception ex)
            {
                // Si falla aquí, esto evitará que la app continúe silenciosamente
                throw new System.Exception($"Error crítico en MailKit: {ex.Message}", ex);
            }
            finally
            {
                await client.DisconnectAsync(true);
            }
        }
    }
}