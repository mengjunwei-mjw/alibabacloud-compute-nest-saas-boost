package org.example.common.param.parameter;

import java.io.Serializable;
import java.util.Map;
import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateConfigParameterParam implements Serializable {

    @NotNull(message = "name is mandatory for this action.")
    private String name;

    @NotNull(message = "value is mandatory for this action.")
    private String value;

    // 是否加密，默认为False
    @Builder.Default
    private Boolean encrypted = false;

    private Map<String, String> tags;
}
