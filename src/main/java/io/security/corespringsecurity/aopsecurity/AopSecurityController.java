package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.domain.dto.AccountDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AopSecurityController {

    @Autowired
    private AopMethodService aopMethodService;

    @Autowired
    private AopPointcutService aopPointcutService;

    @Autowired
    private AopLiveMethodService aopLiveMethodService;

    @GetMapping(value="/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') and #account.username == principal.username")
    public String preAuthorize(AccountDto account, Model model, Principal principal){
        model.addAttribute("method","Success @PreAuthorize");

        return "aop/method";
    }

    @GetMapping(value="/methodSecured")
    public String methodSecured(Model model){
        aopMethodService.methodSecured();
        model.addAttribute("method","Success MethodSecured");
        return "aop/method";
    }

    @GetMapping(value="/pointcutSecured")
    public String pointcutSecured(Model model){
        aopPointcutService.pointcutSecured();
        aopPointcutService.notSecured();

        model.addAttribute("method", "Success Pointcut Secured");

        return "aop/method";
    }

    @GetMapping(value="/liveMethodSecured")
    public String liveMethodSecured(Model model){
        aopLiveMethodService.liveMethodSecured();
        model.addAttribute("method","Success LiveMethodSecured");
        return "aop/method";
    }
}
