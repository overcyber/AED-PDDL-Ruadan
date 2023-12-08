(define (problem test-network-enumeration-02)
    (:domain network-enumeration)
    ; Definindo os objetos necessários para testar todas as ações
    (:objects
        host1 host2 - host
        service1 - web_service
        service2 - mail_service
        port22 port80 port443 - port
        version1 version2 - version_type
    )

    ; Estado inicial - definindo um cenário básico
    (:init
        ; Hosts e portas iniciais
        (not (host_scanned host1))
        (not (host_scanned host2))
        (not (port_open port22 host1))
        (not (port_open port80 host1))
        (not (port_open port443 host2))

        ; Serviços iniciais não detectados
        (not (service_detected service1 port80 host1))
        (not (service_detected service2 port443 host2))

        ; Versões dos serviços não conhecidas
        ; Predicado no dominio requer 5 arg

	(not (service_version service1 version1 port80 host1))
	(not (service_version service2 version2 port443 host2))	


        ; Vulnerabilidades iniciais desconhecidas
        (not (vulnerability_known version1 service1))
        (not (vulnerability_known version2 service2))

        ; Nenhum alvo de exploração identificado inicialmente
        (not (best_exploitation_target port80 host1))
        (not (best_exploitation_target port443 host2))
    )

    ; Definindo o objetivo do problema
    (:goal
        (and
            ; O objetivo é realizar uma série de ações para testar o domínio
            (host_scanned host1)
            (host_scanned host2)
            (port_open port22 host1)
            (service_detected service1 port80 host1)
            (service_version service1 version1 port80 host1)
            (vulnerability_known version1 service1)
            (best_exploitation_target port80 host1)
        )
    )
)

