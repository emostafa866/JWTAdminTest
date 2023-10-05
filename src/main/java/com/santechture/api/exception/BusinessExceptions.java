package com.santechture.api.exception;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class BusinessExceptions extends Exception{
    public Object[] args;

    public String message;

    public Exception e;

    public BusinessExceptions(String message, Object[] args){
        super(message);
        this.message=message;
        this.args=args;
        log.error(message);
    }

    public BusinessExceptions(String message){
        super(message);
        this.message=message;
        this.args=new Object[]{};
        log.error(message);
    }

    public BusinessExceptions(Exception e){
        super(e.getMessage());
        this.message=e.getMessage();
        this.args=new Object[]{};
        this.e = e;
        log.error(e.getMessage(),e);
    }


}
