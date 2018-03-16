package ua.com.owu.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//@Configuration
//@EnableWebSecurity
//@ComponentScan("ua.com.owu.*")
public class SecurityConfigUSLESSEXAMPLE  /*extends WebSecurityConfigurerAdapter*/{

    @Autowired
    UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
    private InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryUserDetailsManagerConfigurer(){
        return new InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder>();
    }

    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth, AuthenticationProvider provider) throws Exception {
        inMemoryUserDetailsManagerConfigurer()
                .withUser("a")
                .password("a")
                .authorities("ADMIN")
                .and()
                .configure(auth);
        auth.authenticationProvider(provider);

    }

//    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/moderator/**").hasRole("MODERATOR")
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/logMe")
                .defaultSuccessUrl("/WEB-INF/pages/index.jsp",true)
                .passwordParameter("password")
                .usernameParameter("username")
                .and()
                .logout().logoutUrl("/logout")/*.logoutSuccessUrl("/")*/
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")).and()
                .csrf();
    }
}


/*in memory*/
//    @Autowired
//    public void globalConfiureGlobal(AuthenticationManagerBuilder auth, AuthenticationProvider provider) throws Exception {
//        auth.inMemoryAuthentication().withUser("adm").password("adm").roles("ADMIN");
//
//    }
//
/*custom*/
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(authenticationProvider());
//    }
