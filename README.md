# Asterisk-Laboratorio-Portaria-Autonoma

## 1. Introdução

A portaria autonoma é um sistema utilizado em alguns condominios residenciais, onde a chamada passa por etapas, onde primeiro toca em um ponto e em seguida ocorre transbordo para outro pponto. 
Por exemplo, nestes cenários a chamada é encaminhada primeiramete no interfone na residencia de um morador e caso não seja atendida em 20 segundos, é redirecionada para o softphone instalado no 


## 2. Sobre o laboratório

O cenário é composto da seguinte forma. 

-ATA (modelo utilizado KAP320X), onde o lado SIP esta registrado em uma conta PJSIP do Asterisk, a poarta FXO deste ATA esta conectado em uma posição de ramal da central analógica

-A central analógica por sua vez distribui ramais analógicos para os apartamentos conectado em interfones.

-Além disso no softphone existe um ramla VoIP em um softphonme registrado em uma conta PJSIP no Asterisk, por sua vez este ramal precisa possuir o mesmo número que o apartamento.  

Este cenário tem por finalidade ligar para dois pontos, primeiro para o interfone do apartamento, caso não eja atendida em 20 segundos ela é transferida para o ramal que esta no celular. 

Dois pontos importantes a serem anotados é que o ATA precisa ter a opção "200OK após atendimento pelo FXO", pois vai enviar o 200OK do atendimento somente quando a chamada for atendida no lado FXO, assim o
Astersik entende que a chamada só é atendida quando o interfone tirar o interfone do gancho. O segundo ponto importante a ser anotado é que o ramal PJSIP no softphone do celular precisa ter o mesmo numero que o apartamento, pois 
o número é discado uma vez só, e o transbordo é autopmatico. 


No Asterisk o contexto precisa possuir a seguinte forma de discagem Dial(PJSIP/${EXTEN}@<TRONCO>,20). Importante que seja desta forma pois o número discado vai ser encaminhado para o tronco, 
chegando o número discado no ATA e este por sua vez fazendo o processo de convergencia SIP > FXO.   


## 3. Como Instalar o Laboratório:

1 - Priomeiramente precisa ter instalado o Asterisk 22. 

2 - Baixe o conteudo deste repositório. 

3 - Em seguida substitua os arquivos pjsip.conf e extensiosns.conf (que estão dentro da pasta /etc/asterisk). Adicione os arquivos pjsip_additional.conf e extensiosns_additional.conf


## 4. Como Montar o Laboratório:

Importante 1: Habilitar a opção "200OK após atendimento pelo FXO"

Importante 2: O ramal utilizado como apartamento é 22 pois esta é a faixa da central analógica. 

4.1. Cenario 1:
- No Facial/porteiuro registre o ramal 5000 (senha: sip1234)
- No ATA registre a conta 5010 (senha: sip1234)
- Na sofphone em um smartphone, regsitre a conta 22 (senha: sip1234). 
- Conecte um ramal analógico da central na porta FXO do ATA
- Crie um rota no ATA com sentido SIP > FXO
- Apartamento/Ramal SIP: 22 (contexto: cenario-1-entrada)


 <img width="1291" height="583" alt="cenario1-port" src="https://github.com/user-attachments/assets/960fa114-56f3-4ff0-9bc7-2599af421f6f" />


4.2. Cenario 2:
- No Facial/porteiuro registre o ramal 6000 (senha: sip1234)
- No ATA registre a conta 6010 (senha: sip1234)
- Na sofphone em um smartphone, regsitre a conta 22 (senha: sip1234). 
- Conecte um ramal analógico da central na porta FXO do ATA
- Crie um rota no ATA com sentido SIP > FXO, e um transbordo de 20 segundos para o SIP
- Apartamento/Ramal SIP: 22 (contexto: cenario-2-entrada)

<img width="1291" height="583" alt="cenario-2-port" src="https://github.com/user-attachments/assets/545b51a5-9eb8-428b-9e35-9cb777f220e3" />


