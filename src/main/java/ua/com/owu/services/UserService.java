package ua.com.owu.services;

import org.springframework.data.domain.Page;
import ua.com.owu.entity.User;

import java.util.List;

public interface UserService {

    void save(User user);

    User findOne(int id);

    List<User> findAll();

    void delete(User user);

    void delete(int id);

    Page<User> allUsersPageable(Integer page);



}
