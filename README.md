# Proxmox_NAT_Patch
Proxmox patch to create firewall NAT rules for web UI

# Проблематика
Все пользователи Proxmox уже почувствовали всю мощь это продукта, а IT администраторы систем витруализации вовсю используют Proxmox в production. Однако, как и все бесплатные продукты есть ряд недоработок, нервирующие каждый день. Чтож сегодня мы сделаем одной проблемой меньше!

Итак рассматривая общую архитектуру облачно/контейнерных решений в простом варианте архитектура сети выглядит следующим образом (мой опыт, не претендую на истину):

![map](https://github.com/Code-Exec/Proxmox_NAT_Patch/blob/master/img/Classical%20PVE.png)

Немного поясню. Интерфейс "eth0" - физический интерфейс. Как правило из коробки Proxmox VE настраивается на "vmbr0" как виртуальный интерфейс сбридженный с физическим "eth0". Вероятно это для упрощения настройки будущей балансировки в случае существования нескольких каналов интернет. Однако в случае с одним каналом интернет это никакого значения не имеет. Можно было бы насртоить и на физический интерфейс "eth0". Интерфейсы "vmbr0", "vmbr1" - виртуальные, существуют только в PVE. Итак, вот мы создавали несколько виртуальных машин (или контейнеров) и первая проблема - как управлять их сетевым доступом? Локальный трафик в рамках виртуального сегмента сети "192.168.0.1/24" управляется легко. Встроенный в PVE Firewall (основанный на iptables) прекрасно с этим справляется, но как прокинуть порты во внутрь и пропустить трафик наружу?

Официальный сайт нам предлагает изумительное решение.  - [Masquerading (NAT) with iptables](https://pve.proxmox.com/wiki/Network_Configuration#_masquerading_nat_with_tt_span_class_monospaced_iptables_span_tt).

Формально они предлагают писать ручками правила NAT между vmbr0 и vmbr1.

Это как у купили вы Теслу, а заводить ее с толкача. Казалось бы тривиальная задача...

# В чем идея?
Да конечно, поначалу я как и все пошел пропихивать в iptables свои правила. Причем тут еще один ньюанс, PVE Firewall на виртуальных машинах тоже работал и для каждого NAT правила нужно было создать еще одно в интерфейсе PVE. В последствии PVE Firewall на виртуальных машинах отключался (изолированная виртуальная сеть не сильно снижала безопасность без него). Но одно дело когда машин 2 и другое когда 20. На память не упомнишь кому какие порты раздавал, у какой машины есть выход на сторонние узлы... ребут или перезапуск служб мог вычистить все созданные правила...
Постепенно я написал скрипт на bash для более менее комфортного управления всем этим ужасом и готовился уже создавать более красивое решение на python.
Я даже думал пойти ужасным путем и поднять прокси внутри виртуальной сети...
Но тут у меня возник вопрос в голове: 
`"Стоп, ведь вся проблема в том что интерфейс PVE Firewall не позволяет вводить правила NAT". `
Да и в архитектуре должен быть один firewall. Нет смысла их плодить и тратить время на их обслуживание. Сохраняя правила NAT в стандартном интерфейсе PVE Firewall мы получаем массу преимуществ: видимость всех правил разом, сохранение вместе с ВМ, не нужно лезь в консоль.
Конечная идея была сформирована: **научить интерфейс PVE Firewall понимать правила NAT !**
# Решение
Решение представляет из себя создание дополнительного правила iptables(NAT) при добавлении стандартного правила PVE через интерфейс, тригер для создания - строка "Comment" начинается с "NAT".

# Установка

**1. Патчим pve-firewall.**

Скачиваем файлы "patcher.sh", "diff.txt" и кладем их в любое удобное место в одну папку. Переходим в эту папку и пишем в консоле - 
        
        $ ./patcher.sh run

Эта команда пропатчит файл `/usr/share/perl5/PVE/Firewall.pm`, сделав бэкап. Если все прошло успешно то увидим "Patch done"ю

**ВНИМАНИЕ!** В модифицированном файле есть строка для привязки к внешнему интерфейсу (необходим для NAT правил).

        my $ext_if = 'vmbr0'; #external interface

Если у вас другая схема архитектуры, то измените значение на свой интерфейс.

**2. Вносим изменения необходимые для NAT**

По рекомендациям офицаильного сайта - [Link](https://pve.proxmox.com/wiki/Network_Configuration#_masquerading_nat_with_tt_span_class_monospaced_iptables_span_tt)

Изменяем файл /etc/network/interfaces

        auto vmbr1
        #private sub network
        iface vmbr1 inet static
                address  10.10.10.1
                netmask  255.255.255.0
                bridge-ports none
                bridge-stp off
                bridge-fd 1

                post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
                post-up   iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1
                post-down iptables -t raw -D PREROUTING -i fwbr+ -j CT --zone 1

По факту мы добавляем три строки к нашему интерфейсу виртуальной сети (он же будет шлюзом для всей сети)

                post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
                post-up   iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1
                post-down iptables -t raw -D PREROUTING -i fwbr+ -j CT --zone 1

Первая строка - добавляет возможность пропускать "проходящий трафик", без нее NAT вообще не будет работать.

Вторая - исправляет проблему с contrack (часть для NAT позволяющая не писать двойные правила на вход и выход, основывается на анализе состояния соединений и флагах пакетов). Проблема в том что contrack иногда запутывается в трафике между виртуально и не виртуальной сетями. 

Первые две срабатывают при включении интерфейса. Третья при отключении, отменяет вторую...

**3. Перезапускаемся** 

Лучше перезапустить весь сервер. Но если это не возможно то можно выполнить в консоли:

        service pvedaemon restart
        service pvepoxy restart
        pve-firewall restart

# Использование

**Правила NAT создаются только когда комментрий правила начинается с строки "NAT"!**

Привила применяются не моментально... Иногда дело может доходить до минуты. Но очень редко. Архитектура решения такова, что правила все очищаются, потом создаются новые.

Пример NAT in:

![Sample_NAT_in](https://github.com/Code-Exec/Proxmox_NAT_Patch/blob/master/img/Sample_NAT_in.PNG)

В этом примере по мимо стандартного правила разрешающего 123.123.123.123:822 -> 10.10.10.107:22 создастся еще одно NAT. То есть создав такое правило и постучавшись с IP 123.123.123.123 на порт 822 на IP адрес нашего сервера, мы будем прокинуты на 10.10.10.107:22 . Если не заполнить источник, то любой IP сможет подключиться через порт 822.

**ВАЖНО!** В моей архитектуре все виртуальные машины имеют статический IP поэтому создавая такое правило я точно знаю на какую машину оно уйдет. Очень удобно использовать VMID в качестве последней цифры IP, но это лично мое мнение.

Пример NAT out:

![Sample_NAT_out](https://github.com/Code-Exec/Proxmox_NAT_Patch/blob/master/img/Sample_NAT_out.PNG)

В этом примере все аналогично. Создастся второе правило NAT пробрасывающее с 10.10.10.105 (это конкретная VM) трафик на 123.123.123.123:443. То есть если мы с этой VM попробуем подключиться к 123.123.123.123:443 сработает NAT и нас пропустит.

**ВАЖНО!** Элиасы или псевдонимы пока что не поддерживаются. Использовать придется только IP.

# Удаление

Удаление происходит в том же порядке:
1. Вводим команду -  
> ./patcher.sh rollback
Эта команда восстановит оригинальный файл из бэкапа. Если все прошло успешно увидим "Rollback done".
2. Удаляем строки из "/etc/network/interfaces".
3. Перезагружаемся.