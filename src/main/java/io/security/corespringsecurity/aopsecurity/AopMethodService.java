package io.security.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopMethodService {
    //Test
    public void methodSecured(){
        System.out.println("Method Secured");
    }
}
