package ua.com.owu.services.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import ua.com.owu.entity.User;
import ua.com.owu.services.MailService;

import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
@Service
@PropertySource("classpath:email.properties")
public class MailServiceImpl implements MailService {
    @Autowired
    JavaMailSender javaMailSender;
    @Autowired
    Environment env;

    public void send(User user) {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);
        try {
            mimeMessage.setFrom(new InternetAddress(env.getProperty("email.username")));
            helper.setTo(user.getEmail());
            helper.setText("Dear " + user.getUsername() + ", wisit our <a href = 'http://owu.com.ua'>site</a> ",true);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
            javaMailSender.send(mimeMessage);

    }
}
