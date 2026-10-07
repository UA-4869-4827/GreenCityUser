package greencity.security.dto.ownsecurity;


import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class GoogleAccessTokenDTO {

    @NotBlank
    private String idToken;
}
