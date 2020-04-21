# KISSACT - Keep It Stupid Simple Automatic Contact Tracing

## Introduction

KISSACT est une contribution aux projets d'app pour smartphones (+objets connectés) et de serveur (HTTP) d'autorité sanitaire pour permettre un traitement automatique et **individualisé** des mesures de prévension contre une pandémie, comme celle du Covid-19.

Le coût économique mondial de meusures de confinement indifférencié est gigantesque, plusieurs dizaines de milliers de milliards de dollars. Par ailleurs, le déconfinement indifférencié, risquant de laisser repartir la pandémie, conduit à terme à des coûts tout aussi importants. Au final, c'est la prospérité de pays entiers, la liberté des peuples et la santé des humains qui sont menacées. L'investissement dans un coût de développement d'une app de contact tracing est ridiculement faible vu l'enjeu économique. Notre contribution est toutefois bénévole. Ma demande d'aide auprès du ministère Français des armées pour un montant de 5000€ a été refusée.

Dans ce context, même sans expérience précédente, s'aider d'un outil numérique est nécessaire pour automatiser et améliorer la pertinence des opérations classiques et manuelle de 'contact tracing' conduites par des épidémiologistes via des intrerviews.

KISSACT est à ce jour (21 Avril) un simple programme Python de moins de 100 lignes.
Il est la référence pour des implémentations
- d'une **app** pour smartphone (iOs et Android) de contacts BLE,
- d'un **serveur** web (backend sous responsabilité des épidémiologistes).

L'approche suivie de stratégie de dépistage individualisé est un processus d'optimisation sous contrainte, stochastique, multi-factoriel et non linéaire. La configuration du modèle est toujours définie par les scientifiques et non par les développeurs de l'app. Un consensus le plus large possible doit être obtenu et ce en toute transparence avec les citoyens. Ce modèle est téléchargé et mis à jour quotidiennement sur les smartphones ayant installé l'app. Ainsi, localement l'application des données personnelles au modèle fournit une liste de consignes individualisée à observer par le propriétaire du smartphone. 

Si les politiques et les juristes venaient à imposer autoritairement des solutions scientifiquement arbitraire, archaiques et sous-optimales, ils deviendraient responsables face aux peuples, qui aspire à la paix, de nombreux décès d'innocents, par incompétence ou négligeance à vouloir individualiser les mesures.

Sachant que l'efficacité d'une app de contact tracing est fonction quadratique de son taux d'utilisation, il est logique de ne pas laisser une quelconque liberté aux citoyens à ne pas utiliser cette app en période avérée de pandémie. Il n'y a aucun consentement à demander car la situation est analogue à une vaccination. Le refus de se faire vacciner, tout comme celui d'activer cette app lors des déplacements relève alors d'un danger collectif de santé public. 
Par ailleur, il est important de laisser une concurrence saine entre projets de développement de solutions numériques, mais lors de la mise en oeuvre, il sera essentiel pour le bien de tous, de choisir le même système, avec au mmoins des apps compatibles entre elles.

Aujourd'hui (21 Avril 2020), le projet DP-3T est le plus prometeur, le plus diffusé et le plus avancé. Le projet ROBERT ne présente que de la documentation de protocole et souffre d'une approche plus centralisée que DP-3T.
Notre objectif avec KISSACT n'est pas de remplacer ces projets financés, d'universitaires compétents, soutenus par les puissances publiques, mais d'obliger à prendre en compte des exigences citoyennes et scientifiques qui pourraient être oubliées. Notre totale indépendance, comme start-up ne touchant aucun revenu, est le meilleur garant que l'intéret citoyen soit bien défendu.

KISSACT veut simplement améliorer la transparence et la compréhension des protocoles de Contact Tracing. C'est un peu un 'Contact Tracinng pour les nulls' !
J'invite tous les currieux, même les jeunes, sans être obligatoirement informaticien, à se plonger dans le code Python de moins de 100 lignes, à exécuter l'exemple fourni avec les quatre utilisateurs virtuels: Alice, Bob, Carol et David.

## Examinons ce code ensemble

Ce code simule tous: les utilisateurs, les serveurs, le temps. C'est un modèle donc par définition incomplet, généralement faux, réducteur, mais un modèle est quand même utile pour programmer correctement des app et des serveurs, robustes, maintanable, efficasses et respectants les principes d'optimalité d'ingenierie.

Pour déclarer un utilisateur, on crée un objet *ctApp* () avec le pseudo et l'age de son propriétaire, ce qui peut sembler violer les principes de protection des données privées. Le nom n'est sert qu'à distinguer les objets et faciliter la compréhension des résultats de simulation. L'age est un exemple de donnée personnelle, comme les positions géographiques des déplacements, qui peuvent être utilisées par le modèle de risque téléchargé sur le téléphone pour déterminer la meilleure mesure individualisée à prendre quotidiennement. En aucun cas ces données sont transmises au serveur. 

Un objet serveur 'serverCT' est créé, sous la responsabilité des autorités sanitaires. Ce serveur que l'on peut qualifié de public, ne contient rien de secret sur les personnes ou sur le fonctionnement des app. Il est simplement protégé de toute personne malveillante qui voudrait modifier ou effacer ces données partagées entre tous. 

Dans le code KISSACT, Il n'y a aucune constante de temps. C'est volontaire. Tout le modèle est configurable par les épidémiologistes, et des paramètres peuvent changer quotidiennement dans certaines limites contrôlées par l'app. Il n'est pas possible pour quelqu'un qui predrait le contrôle du serveur, de reprogrammer complètement les apps.
En particulier, il n'y a pas de découpage par jour comme dans DP-3T. La notion de jour n'a pas de sens pour le virus, c'est juste un repère statistique. De même, la période de référence, nommée EPOCH dans DP-3T, peut être variable.
Dans KISSACT, la méthode 'next' qui simule l'environnement est ici associée au serveur, procède à un changement d'indentifiant BLE (Id par la suite) pour tous les utilisateurs. Les vraie app changent seule d'Id en fonction du temps.

La fonnction 'contact' simule un contact entre deux personnes en précisant la durée de ce contact, la proximité (inverse de la distance) de ce contact. Dans l'application réelle, on peut introduire diverse options qui vont légèrement modifier l'évaluation du risque de contagion.
Une option "plexiglass" pour indiquer un mur leger afin de tenir compte de mesure de protection physiques entre persones. On peut aussi prévoir une option qui indique si tout l'entourage porte un masque, partiellement ou pas de tout.

Les contacts s'enregistrent de manière symétrique comme dans la vie réelle. 
Une personne malveillante peut espioner les message émis avec une importante distance en utilisant une antenne directionnelle, sans emmetre de message.
Elle peut aussi envoyer de très nombreux messages (attaque DOS) pour saturer les smartphones à proximité.
Ce sont les couches basses qui filtrent ces attaques. L'API commune Apple-Google devrait faciliter le travail.

Le scénario est le suivant:
Au debut, les quatres personnes restent séparées
Ensuite Alice rencontre Bob, 
puis Bob déjeune avec Carol,
Quelque temps plus tard, il se promène avec elle dans le parc
Enfin, David rend visite à Alice.

Imaginons que Carol développe des symptômes au Covid-19. Son médecin lui procure un droit à être testé et il s'avère qu'elle est positive. Son médecin fait générer par le serveur un code à usage unique, qui servira à Carole à déclarer qu'elle est contagieuse. La saisie de code évite que n'importe qui, robot compris se séclare contagieux.

Carole est libre d'informer le serveur des contacts passés avec le degré de détail qu'elle désire. Plus elle donne d'information, et meilleures sera l'analyse de risque qui en sera déduite. 
L'app lui représente sa liste de contacts et elle peut choisir de ne pas diffuser certains, à certaines date ou en fonction du lieu enregistré du contact (si GPS/GSM activé).

Dans notr exemple, David est aussi malade et décide que plutôt que de fournir une liste, il donne simplement sa clé racine, ce qui permettra au serveur de reconstituer tout son historique de contact.

Le serveur va partager publiquement l'historique des contacts des personnes infectées, sans aucune autre données de géolocalisation, sans connaitre l'identité ni le nombre de personnes infectées.

Tous les jours, en utilisant une connexion filaire ou wifi pour les téléphones sans carte SIM, l'app intéroge le serveur pour avoir la mise à jour des contacts des personnes infectées et la mise à jour du modèle d'épidémiologie.
Après application de ce modèle, l'app est capable de proposer un ensemble de mesures individuelle à prendre.

Il n'y a en revanche aucun mécanisme pour vérifier ensuite l'application des mesures recommandées.

Si avec cet outils et d'autres, Rt passe durablement en dessous de 1 ou si un vaccin est trouvé, alors il y aura de moins en moins de déclarations Convid-plus sur le serveur.
Comme le risque de contagion est fonction des dates des rencontres passées, le risque va tendre vers zéro. L'app ne sera plus utile.

AU niveau de l'interface de l'app, je recommande d'afficher un indicateur "bulle" (voir https://adox.io/bulle.pdf) qui indique au porteur s'il respecte ou pas les règles de distanciation.

## Extensions

Il est possible lors d'un contact d'effectuer un paiement numérique instantané, dans le cadre d'un système de crédit mutuel. Contraireemnt à une monnaie, il est autorisé d'avoir un compte avec un solde négatif, jusqu'à une certaine limite. La valeur positive est aussi limitée.
L'app affiche le solde courant.
Le paiement ne doit être possible qu'en zone Orange, pour obliger les contractant à s'éloigner l'un de l'autre.

Cette extension demande une déclaration auprès d'un service d'état civil afin de pouvoir discriminer les humains entre eux et n'autoriser qu'un seul compte par personne, comme le LivertA. Une telle autorisation d'andettement, une avance de ligne de crédit, sans intéret, à vie, n'est pas possible pour les personnes morales, les robots ou les IA.

L'unité monétaire est universelle. Elle est initialisée avec une valeur approximative de l'énergie d'1kW, soit environ 10 centimes d'euros. Le prix de chaque produit échangeable par ce système comptable est libre.

Parallèlement à cette fonction de paiement, il est possible d'instaurer une forme dégradée de crédit mutuel avec l'auro en forçant les banques privées à autoriser un découvert gratuit, à vie, pour tout citoyen adulte. 
La limite du découvert, décidée démocratiquement, peut être initialement de 10.000€ et être augmentée par la suite pour ateindre par exemple 120.000€ à l'horizon 20230 (conseils de l'économiste Thomas PiKetti).

Le paiement pourra aussi se réaliser via un objet. C'est pour cette raison qu'il doit être possible d'implémenter un protocole KISSACT sur un appareil BLE autre qu'un smartphone. Plusieurs projets sont à l'étude, à base d'ESP32, de nRF52 ou avec une carte RaspberryPi-zéro équipée d'une batterie (hat). 

## Contact

laurent.fournier@adox.io

