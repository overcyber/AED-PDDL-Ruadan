(define (domain network-enumeration)
    (:requirements :strips :typing :conditional-effects)

    ; Definindo os tipos
    (:types
        host
        port
        service
        version
    )

    ; Predicados para descrever o estado do domínio
    (:predicates
        (host_scanned ?h - host)
        (port_open ?p - port ?h - host)
        (service_detected ?s - service ?p - port ?h - host)
        (service_version ?s - service ?v - version ?p - port ?h - host)
        (vulnerability_known ?v - version ?s - service)
        (exploitation_attempted ?p - port ?h - host)
        (exploitation_successful ?p - port ?h - host)
        (best_exploitation_target ?p - port ?h - host)
    )


    ; Ação para escanear um host
    (:action scan_host
        :parameters (?h - host)
        :precondition (not (host_scanned ?h))
        :effect
        (and
            (host_scanned ?h)
            ; Supõe-se que algumas portas são descobertas e outras não
            ; Os efeitos condicionais podem ser adicionados com base em regras específicas
        )
    )

    ; Ação para escanear uma porta específica em um host
    (:action scan_port
        :parameters (?p - port ?h - host)
        :precondition (and (host_scanned ?h) (not (port_open ?p ?h)) (not (port_closed ?p ?h)))
        :effect
        (and
            ; Efeito condicional para determinar se a porta está aberta
            (when (some_condition_for_open_port) (port_open ?p ?h))
            (when (not (some_condition_for_open_port)) (port_closed ?p ?h))
        )
    )
    ; Ação para verificar um serviço em uma porta aberta
    (:action check_service
        :parameters (?s - service ?p - port ?h - host)
        :precondition (and (port_open ?p ?h) (not (service_detected ?s ?p ?h)))
        :effect
        (service_detected ?s ?p ?h)
        :precondition (and (port_open ?p ?h) (service_detected ?s ?p ?h))
        (and
            ; Supõe-se que a versão do serviço seja determinada aqui
            (service_version ?s ?some-version ?p ?h)
            ; Efeitos condicionais podem ser adicionados para refletir diferentes versões e suas vulnerabilidades
        )
    )
    ;; 
    ;; (:action determine_service_version
    ;;     :parameters (?s - service ?p - port ?h - host)
    ;;     :precondition (and (port_open ?p ?h) (service_detected ?s ?p ?h))
    ;;     :effect
    ;;     (and
    ;;         ; Supõe-se que a versão do serviço seja determinada aqui
    ;;         (service_version ?s ?some-version ?p ?h)
    ;;         ; Efeitos condicionais podem ser adicionados para refletir diferentes versões e suas vulnerabilidades
    ;;     )
    ;; )


    ; Ação para determinar a versão de um serviço
    (:action determine_service_version
        :parameters (?s - service ?p - port ?h - host)
        :precondition (and (port_open ?p ?h) (service_detected ?s ?p ?h))
        :effect
        (and
            ; Supõe-se que a versão do serviço seja determinada aqui
            ; Por exemplo, a versão pode ser identificada e associada ao serviço
            (service_version ?s ?some-version ?p ?h)
            ; Efeitos condicionais podem ser adicionados para refletir diferentes versões e suas vulnerabilidades
        )
    )



    ; Ação para verificar se a versão de um serviço tem vulnerabilidades conhecidas
    (:action check_vulnerability
        :parameters (?s - service ?v - version ?p - port ?h - host)
        :precondition (and (service_version ?s ?v ?p ?h) (not (vulnerability_known ?v ?s)))
        :effect
        (and
            ; Verifica se existe uma vulnerabilidade conhecida para a versão
        )
    )

    ; Ação para escolher o melhor alvo para exploração
    (:action select_best_exploitation_target
        :parameters (?p - port ?h - host)
        :precondition (and 
            (port_open ?p ?h) 
            (not (best_exploitation_target ?p ?h))
            ; Adicionando a condição de que deve haver um serviço vulnerável na porta
            (exists (?s - service) (and (service_detected ?s ?p ?h) (service_vulnerable ?s ?p ?h)))
        )
        :effect
        (and
            ; Marca a porta como o melhor alvo para exploração com base na presença de serviços vulneráveis
            (best_exploitation_target ?p ?h)
            ; Efeitos adicionais podem ser considerados para refletir a priorização da exploração
        )
    )


    ; Ação para tentar explorar uma porta aberta
    (:action exploit_port
        :parameters (?s - service ?p - port ?h - host)
        :precondition (and (best_exploitation_target ?p ?h) (vulnerability_known ?v ?s))
        :effect
        (and
            (exploitation_attempted ?p ?h)
            ; Efeito condicional para determinar se a exploração foi bem-sucedida
        )
    )
)
