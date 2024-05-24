package com.rais.realestate.authentification.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}