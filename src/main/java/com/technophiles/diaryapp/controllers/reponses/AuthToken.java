package com.technophiles.diaryapp.controllers.reponses;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class AuthToken {
    private String token;
    private Long id;
}
