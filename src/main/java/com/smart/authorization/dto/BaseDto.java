package com.smart.authorization.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.Setter;

import java.io.Serializable;
import java.time.Instant;

/**
 * Author: rustam.akhmedov@gmail.com
 * Date: 5/8/18
 * Time: 11:41
 */
// TODO Add @JsonPropertyOrder to all sub-classes
@Data
public class BaseDto implements Serializable {

    @Setter(onMethod = @__(@JsonIgnore))
    @JsonProperty
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ssZ",
            timezone = "UTC")
    private Instant createdDate;

    @Setter(onMethod = @__(@JsonIgnore))
    @JsonProperty
    @JsonFormat(shape = JsonFormat.Shape.STRING,
            pattern = "yyyy-MM-dd'T'HH:mm:ssZ",
            timezone = "UTC")
    private Instant updatedDate;
}
