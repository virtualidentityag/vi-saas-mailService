package de.caritas.cob.mailservice.config;

import de.caritas.cob.mailservice.filter.StatelessCsrfFilter;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.csrf.CsrfFilter;

/** Provides the Security configuration. */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  public static final List<String> WHITE_LIST =
      List.of(
          "/mails/docs",
          "/mails/docs/**",
          "/v2/api-docs",
          "/configuration/ui",
          "/swagger-resources/**",
          "/configuration/security",
          "/swagger-ui.html",
          "/webjars/**",
          "/actuator/health",
          "/actuator/health/**",
          "/translations",
          "/translations/**");

  @Value("${csrf.cookie.property}")
  private String csrfCookieProperty;

  @Value("${csrf.header.property}")
  private String csrfHeaderProperty;

  @Bean
  public SecurityFilterChain configure(HttpSecurity http) throws Exception {

    var httpSecurity =
        http
            .addFilterBefore(
                new StatelessCsrfFilter(csrfCookieProperty, csrfHeaderProperty), CsrfFilter.class);

    httpSecurity
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
        .and()
        .authorizeRequests()
        .anyRequest()
        .permitAll();

    return httpSecurity.build();
  }
}
