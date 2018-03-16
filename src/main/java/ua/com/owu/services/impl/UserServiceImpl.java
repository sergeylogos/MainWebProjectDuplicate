package ua.com.owu.services.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.repository.query.Param;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ua.com.owu.dao.UserDAO;
import ua.com.owu.entity.User;
import ua.com.owu.services.UserService;

import java.util.List;
@Service
public class UserServiceImpl implements UserDetailsService, UserService {
    @Autowired
    private UserDAO userDAO;
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        return findByName(name);
    }

    public void save(User user) {
        userDAO.save(user);
    }

    public User findOne(int id) {

        return userDAO.findOne(id);
    }

    public List<User> findAll() {

        return userDAO.findAll();
    }

    public void delete(User user) {
            userDAO.delete(user);
    }

    public void delete(int id) {
        userDAO.delete(id);
    }

    public Page<User> allUsersPageable(Integer page) {
        Page<User> all = userDAO.findAll(new PageRequest(page, 5));

        return all;
    }

    public User findByName(@Param("username") String username) {
        return userDAO.findByName(username);
    }
}
