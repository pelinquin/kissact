# KISSACT
Keep It Stupid Simple Automatic Contact Tracing

## Introduction

KISSACT est une contribution aux projets d'app pour smartphones (+objets connectés) et de serveur (HTTP) sanitaire pour permettre un traitement automatique et individualisé des mesures de prévension contre une pandémie, comme celle du Covid-19.

Le coût économique mondial de meusures de confinement indifférencié est gigantesque. Par ailleurs, le déconfinement indifférencié, en laissant repartir la pandémie, conduit à terme des coûts tout aussi importants. Au final, c'est la prospérité des pays, la liberté des peuples et la santé des humains qui sont menacées.

Dans ce context, s'aider d'un outil numérique est nécessaire pour automatiser et améliorer la pertinence des opérations classiques et manuelle de 'contact tracing' conduites par des épidémiologistes via des intrerviews.

KISSACT est à ce jour (21 Avril) un simple programme Python de moins de 100 lignes.
Il est la référence pour des implémentations
- d'une app pour smartphone (iOs et Android) de contacts BLE 
- d'un serveur web (backend épidémiologiste)

L'approche suivie de stratégie de dépistage individualisé est un processus d'optimisation sous contrainte, stochastique, multi-factoriel et non linéaire. La configuration du modèle est défini par les scientifiques, avec le consensus le plus large possible et en toute transparence avec les citoyens. Les politiques et les juristes ne devraient pas imposer autoritairement des solutions archaiques et sous-optimales. Si tel était le cas, il sera possible en sortie de crise de démontrer que les dirigeants avaient du sang sur le mains, et ne méritent pas d'être les représentants des peuples, qui aspirent à la paix.

Sachant que l'efficacité d'une app de contact tracing est fonction quadratique de son taux d'utilisation, il ne faut pas laisser une quelconque liberté aux citoyens à ne pas utiliser cette app en période avérée de pandémie. Il n'y a aucun consentement à demander car la situation est analogue à une vaccination. Le refus de se faire vacciner, tout comme celui d'activer cette app lors des déplacements est un danger collectif de santé public. 
Il est important de laisser une concurrence saine entre projets de développement de solutions numérique, mais lors de la mise en oeuvre, il est essentiel de tous choisir le même système, avec les apps compatibles entre elles.

Aujourd'hui (21 Avril 2020), le projet DP-3T est le plus prometeur et le plus avancé. Le projet ROBERT ne présente que de la documentation de protocole et souffre d'une approche plus centralisée que DP-3T.
Notre objectif avec KISSACT n'est pas de remplacer ces projets financés, universitaires, soutenus par les puissances publiques, mais de obliger à prendre en compte des exigences citoyennes et scientifiques qu'ils auraient omis de satisfaire.

KISSACT veut améliorer la transparence et la compréhension des protocoles de Contact Tracing. C'est un peu le 'Contact Tracinng pour les nulls' !
J'invite tous les currieux, même les jeunes, sans être obligatoirement informaticien, à se plonger dans le code Python de moins de 100 lignes, à exécuter l'exemple fourni avec quatre utilisateurs virtuels: Alice, Bob, Carole et David.

## Examinons ce code ensemble

Ce code simule tous: les utilisateurs, les serveurs, le temps. C'est un modèle donc c'est incomplet, c'est généralement faux, c'est réducteur, mais c'est utile pour programmer des app et des serveurs bien conçus, robustes, maintanable et efficasses.

Pour déclarer un utilisateur, on crée un objet appCT () avec le nom et l'age de son propriétaire, ce qui peut sembler violer les principes de protection des données privées. Le nom facilite la compréhension des résultats de simulation et l'age est un exemple de données particulières, comme les positions géographiques des déplacements, qui ne sont pas utiles dans la détermination du risque brut de contagion au virus, mais qui peuvent être exploité par les modèle épidémiologiques implantés coté serveur pour déterminer la meilleure mesure individualisée à prendre quotidiennement.

Un objet serveur 'serverCT' est créé, sous la responsabilité des autorités sanitaires. Ce serveur ne contient rien de secret pour faire fonctionner les app. Il est simplement protégé de toute personne malveillante qui voudrait modifier ou effacer des données que ce serveur met à disposition de tous. Il peut contenir un dossier privé pour chaque personne qui le souhaiterait, pour y mettre des informations médicales à destination du corps médical, mais toujours de façon anonyme. 

Il n'y a aucune constante de temps dircetment dans le code KISSACT. C'est volontaire pour laisser cela configurable par les épidémiologistes. En particulier, il n'y a pas de découpage par jour comme dans DP-3T. La notion de jour n'a pas de sens pour le virus, c'est juste un repère statistique. De même, la période de référence, nommée EPOCH dans DP-3T, peut être variable et correspond, par la méthode 'next', à un changement d'indentifiant BLE (ID par la suite). Cela peut varier entre une minute et une heure.

La fonnction 'contact' simule un contact entre deux personnes en précisant la durée de ce contact, la proximité (inverse de la distance). Dans l'application réelle, on peut introduire une option "plexiglass" pour indiquer un mur leger afin de tenir compte de mesure de protection physiques entre persones. On peut aussi prévoir une option qui indique si l'entourage est completement masqué, partiellement ou pas de tout.
Les contacts s'enregistrent de manière symétrique. Alice rencontre Bob, Bob déjeune avec Carole, et David rend visite à Alice.

Imaginons que Carole développe des symptômes au Covid-19. Son médecin lui procure un droit à être testé et il s'avère qu'elle est positive. Son médecin fait générer par le serveur un code à usage unique, qui servira à Carole à déclarer qu'elle est contagieuse. La saisie de code évite que n'importe qui, robot compris se séclarent contagieux.

Carole est libre d'informer le serveur de ces contacts passés avec le degré de détail qu'elle désire. Plus elle donne d'information, et plus le travail des épidémiologiste est facilité, meilleures seront les probabilités de risque de contagion pour les autres et donc plus pertinents seront mesures conséillées aux contacts passés avec Carole.
Elle peut founir la liste des IDs correspondant à des contacts, seulement une partie de cette liste si elle veut cacher un déplacement chez son amant. Elle peut chosir d'associer les positions géographiques, si elles ont été enregistrées (GPS ou GSM) lors des contacts. Enfin, elle peut envoyer des données personelles tel que son age ou ses antécédents médicaux.

Le serveur va partager publiquement l'historique de contact des personnes infectées, sans données de géolocalisation, sans connaitre leur identité.

Tous les utilisateurs de l'app vont régulièrement, par exemple tous les jours en utilisant une connxion filaire ou wifi, intéroger le serveur qui retourne à l'appli les nouvelles données de contact des personnes infectées.

Ensuite, localement au téléphone, un vecteur-score est calculé avec plusieurs scénarios possibles
L'utilisateur peut être invité à prendre certaines mesures de protection (port du masque, demande de test, quanrantaine).
Il peut aussi être invité à contacter au téléphone l'autorité sanitaire, qui à la vue de données personnelles, fournies par l'app ou ajouté lors de l'interview, pourra prendre des recommendations encore plus précises, encore plus individualisées.
Il n'y a aucun mécanisme pour vérifier ensuite l'application des mesures recommandées.

Si Rt passe durablement en dessous de 1 ou si un vaccin est trouvé, alors les déclarations Convid-plus ne vont s'épuiser. Le serveur n'aura plus de données nouvelles à fournir. Comme le risque de contagion est fonction de l'age des rencontres passées, le vesteur score de tous lesindividus vont tendre vers la valeur par défaut, indiquant un risque nul. L'app n'est plus utile.

Dans l'interface de l'app, je recommande d'afficher un indicateur "bulle" (voir https://adox.io/bulle.pdf) qui indique au porteur s'il respecte ou pas les règles de distanciation.

## Extensions

Il est possible lors d'un contact d'effectuer un paiement numérique instantané, dans le cadre d'un système de crédit mutuel. Contraireemnt à une monnaie, il est autorisé d'avoir un compte avec un solde négatif, jusqu'à une certaine limite. La valeur positive est aussi limitée.
L'app affiche le solde courant.
Le paiement ne doit être possible qu'en zone Orange, pour obliger les contractant à s'éloigner l'un de l'autre.

Cette extension demande une déclaration auprès d'un service d'état civil afin de pouvoir discriminer les humains entre eux et n'autoriser qu'un seul compte par personne, comme le LivertA. Une telle autorisation d'andettement, une avance de ligne de crédit, sans intéret, à vie, n'est pas possible pour les personnes morales, les robots ou les IA.

L'unité monétaire est universelle. Elle est initialisée avec une valeur approximative de l'énergie d'1kW, soit environ 10 centimes d'euros. Le prix de chaque produit échangeable par ce système comptable est libre.

Parallèlement à cette fonction de paiement, il est possible d'instaurer une forme dégradée de crédit mutuel avec l'auro en forçant les banques privées à autoriser un découvert gratuit, à vie, pour tout citoyen adulte. 
La limite du découvert, décidée démocratiquement, peut être initialement de 10.000€ et être augmentée par la suite pour ateindre par exemple 120.000€ à l'horizon 20230 (conseils de l'économiste Thomas PiKetti).

Le paiement pourra aussi se réaliser via un objet. C'est pour cette raison qu'il doit être possible d'implémenter un protocole KISSACT sur un appareil BLE autre qu'un smartphone. Plusieurs projets sont à l'étude, à base d'ESP32, de nRf52 ou avec une carte RaspberryPi zéro équipée d'une batterie (hat). 

## Contacts

laurent.fournier@adox.io

