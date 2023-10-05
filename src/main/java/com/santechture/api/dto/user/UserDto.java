package com.santechture.api.dto.user;

import com.santechture.api.entity.Admin;
import com.santechture.api.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserDto {

    private Integer userId;

    private String username;

    private String email;
    public UserDto(User user){
        setUserId(user.getUserId());
        setUsername(user.getUsername());
        setEmail(user.getEmail());
    }

}
