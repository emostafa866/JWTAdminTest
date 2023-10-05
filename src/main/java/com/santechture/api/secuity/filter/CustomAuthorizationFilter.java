package com.santechture.api.secuity.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
@Slf4j
@Component
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private final HashSet<String> tokenSet;

    public CustomAuthorizationFilter(HashSet<String> tokenSet) {
        this.tokenSet = tokenSet;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("enter AuthorizationFilter >>");
        if(request.getServletPath().equals("/admin")){
            String appName=request.getHeader("AppName");
            log.info(appName);
            log.info("coming from login page");
            filterChain.doFilter(request,response);
        }else {
            log.info("filter header for token");
            String authorizationToken=request.getHeader("Auth");
            log.info("token is "+authorizationToken );
            if(Objects.nonNull(authorizationToken)&&authorizationToken.startsWith("Bearer ")&& !tokenSet.contains(authorizationToken)){
                try {
                    String token = authorizationToken.substring("Bearer ".length());
                    Algorithm algorithm=Algorithm.HMAC256("SECRET".getBytes());
                    JWTVerifier verifier= JWT.require(algorithm).build();
                    DecodedJWT decodedJWT=verifier.verify(token);
                    String username=decodedJWT.getSubject();
                    List<SimpleGrantedAuthority> authorityList=new ArrayList<>();
                    UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,null,authorityList);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request,response);
                }catch (Exception ex){
                    log.info("error in the token : "+ ex.getMessage());
                    Map<String,String> error=new HashMap<>();
                    error.put("error",ex.getMessage());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                }
            }else {
                log.info("token not starts with bearer"+authorizationToken.length());
                Map<String,String> error=new HashMap<>();
                error.put("error","Invalid Token");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),error);
                filterChain.doFilter(request,response);

            }
        }
    }
}
