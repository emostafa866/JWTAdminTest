package com.santechture.api.validation;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AddUserRequest  implements Serializable {

    @Email(message = "user.invalid.email")
    @NotBlank(message = "user.email.required")
    private String email;
    @NotBlank(message = "user.name.required")
    private String username;


}
