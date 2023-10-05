package com.santechture.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.Serializable;


@Data
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.ALWAYS)
public class GeneralResponse implements Serializable {

    private Integer code;
    private String message;
    private Integer total;
    private Object data;

    public GeneralResponse() {}

    public GeneralResponse(int code, String message) {
        this.code = code;
        this.message = message;
        this.total = 0;
        this.data = new Object[]{};
    }

    public GeneralResponse(int code, String message, int total, Object data) {
        this.code = code;
        this.message = message;
        this.total = total;
        this.data = data;
    }

    public ResponseEntity<GeneralResponse> response(int code, String message, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.total = 0;
        this.data = new Object[]{};

        if(status == null){
            return new ResponseEntity<GeneralResponse>(this,HttpStatus.OK);
        }
        return new ResponseEntity<GeneralResponse>(this,status);
    }

    public ResponseEntity<GeneralResponse> response(int code, String message,Object data) {
        this.code = code;
        this.message = message;
        this.total = 1;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,HttpStatus.OK);
    }

    public ResponseEntity<GeneralResponse> response(int code, String message,Object data,HttpStatus status) {
        this.code = code;
        this.message = message;
        this.total = 1;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,status);
    }

    public ResponseEntity<GeneralResponse> create(int code, String message,Object data) {
        this.code = code;
        this.message = message;
        this.total = 1;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,HttpStatus.ACCEPTED);
    }

    public ResponseEntity<GeneralResponse> response(int total,int code, String message,Object data) {
        this.code = code;
        this.message = message;
        this.total = total;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,HttpStatus.OK);
    }

    public ResponseEntity<GeneralResponse> response(int total,int code, String message,Object data,HttpStatus status) {
        this.code = code;
        this.message = message;
        this.total = total;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,status);
    }



    public ResponseEntity<GeneralResponse> response(Object data) {
        this.code = 200;
        this.message = "Operation Success";
        this.total = 1;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,HttpStatus.OK);

    }

    public ResponseEntity<GeneralResponse> response(Object data,HttpStatus status) {
        this.code = 200;
        this.message = "Operation Success";
        this.total = 1;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,status);

    }

    public ResponseEntity<GeneralResponse> response(Integer code,String message,HttpStatus status) {
        this.code = code;
        this.message = message;
        this.total = 1;
        this.data = null;

        return new ResponseEntity<GeneralResponse>(this,status);

    }

    public ResponseEntity<GeneralResponse> responseWithTotal(int total,Object data) {
        this.code = 200;
        this.message = "Operation Success";
        this.total = total;
        this.data = data;

        return new ResponseEntity<GeneralResponse>(this,HttpStatus.OK);

    }



    public ResponseEntity<GeneralResponse> response(int code, String message, int total, Object data, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.total = total;
        this.data = data;

        if(status == null){
            return new ResponseEntity<GeneralResponse>(this,HttpStatus.OK);
        }

        return new ResponseEntity<GeneralResponse>(this,status);
    }







    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }


    public Object getData() {
        return data;
    }

    public void setData(Object[] data) {
        this.data = data;
    }

}
