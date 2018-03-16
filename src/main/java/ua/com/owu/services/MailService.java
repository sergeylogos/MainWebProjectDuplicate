package ua.com.owu.services;

import ua.com.owu.entity.User;

public interface MailService {
    void send(User user);
}
