package ua.com.owu.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ua.com.owu.entity.User;

public interface UserDAO extends JpaRepository<User, Integer> {

    @Query("from User u where u.username=:username")
    User findByName(@Param("username") String username);

}
