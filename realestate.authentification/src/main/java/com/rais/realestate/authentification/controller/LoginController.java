package com.rais.realestate.authentification.controller;

import com.rais.realestate.authentification.dto.LoginRequest;
import com.rais.realestate.authentification.dto.LoginResponse;
import com.rais.realestate.authentification.service.LoginService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;



@RestController
public class LoginController {

    Logger log = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    LoginService loginService;

    @PostMapping("login")
    public ResponseEntity<LoginResponse> login
            (@RequestHeader(value = "User-Agent", required = false) String userAgent,
             @RequestBody LoginRequest loginRequest) throws Exception {
        log.info("Executing login");

        ResponseEntity<LoginResponse> response = null;
        response = loginService.login(loginRequest);

        return response;
    }
}