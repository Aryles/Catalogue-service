package org.aryles.sec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /*
    Pas besoin pour cette application car la gestion se fait dans un autre microService
    @Override
    protected void configure (AuthenticationManagerBuilder auth) throws Exception{
        // Simple authentification avec la notion noop
        //auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN","USER");
        //auth.inMemoryAuthentication().withUser("user1").password("{noop}1234").roles("USER");
        BCryptPasswordEncoder bcpe=getBCPE();
        auth.inMemoryAuthentication().withUser("admin").password(bcpe.encode( "1234")).roles("ADMIN","USER");
        auth.inMemoryAuthentication().withUser("user1").password(bcpe.encode( "1234")).roles("USER");
    }
*/
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        // super.configure(http);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // http.authorizeRequests().anyRequest().permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/categories/**").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/products/**").permitAll();

        http.authorizeRequests().antMatchers("/categories/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/products/**").hasAuthority("USER");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilterBefore(new JWTAuthorization(), UsernamePasswordAuthenticationFilter.class);
    }
    /*

     aussi comme 1
    @Bean
    public BCryptPasswordEncoder getBCPE(){
        return new BCryptPasswordEncoder();
    }
      */
}
