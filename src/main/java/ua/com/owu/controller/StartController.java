package ua.com.owu.controller;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import ua.com.owu.entity.User;
import ua.com.owu.services.UserService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;


@Controller
public class StartController {

    private static final Logger logger = Logger.getLogger(StartController.class);
    @Autowired
    UserService userService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String index(Principal principal, Model model) {
        model.addAttribute("principal", principal);
        return "index";
    }

    @GetMapping("pageNumber")
    public String pageable(@RequestParam("pageNumber")Integer pageNumber,Model model){
        model.addAttribute("all", userService.allUsersPageable(pageNumber).getContent());
        return "index";


    }

    @GetMapping("/admin")
    public String adminPage(ModelMap model, Principal principal) {
        model.addAttribute("principal", principal);

        return "adminPage";
    }

    @GetMapping("login")
    public String login() {
        return "logingPage";
    }

    @PostMapping("save")
    public String save(@RequestParam("name") String name, @RequestParam("password") String passwprd) {
        User user = new User();
        user.setPassword(passwordEncoder.encode(passwprd));
        user.setUsername(name);
        userService.save(user);
        return "index";
    }


    @GetMapping("/accessDeniedPage")
    public String accessDeniedPage() {
        return "accessDeniedPage";
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
//        return "redirect:/login?logout";
        return "index";
    }

}
