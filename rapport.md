# Rédaction du rapport d'audit

Titre : "Rapport d'audit de sécurité - DiiageCustomerApp"

MERMER Enis _ VANDE MAELE Stijn _ LEROUX Véronique

# Make sure this database password gets changed and removed from the code.

## Identification:

Software qualities impacted:</br> Security - Blocker

## Description:

Location:

> Caltec.StudentInfoProject.Persistence/StudentInfoDbContextFactory.cs</br>
> Line 15:

```
//string connexionString = "tcp:trainingmanagementsqlserver.Database.windows.net:1433;Initial Catalog=TrainingManagement;Persist Security Info=False;User ID=trainingadmin;Password=DevDb2019!;MultipleActiveResultsSets=False;Encrypt=True;ConnectionTimeout=30;";
```

## Impact:

Database passwords should not be disclosed:</br>
`Password=DevDb2019!;`

## Recommendation:

Remove secret !
Use system environmnet variables to access secrets.</br>
`System.getenv("DB_PASSWORD")`

# Make sure disabling CSRF protection is safe here.

## Identification:

Cross-site request forgery CSRF.</br>
Status: To Review

## Description:

Location:

> Caltec.StudentInfoProject.WebUi/Pages/Error.cshtml.cs</br>
> Line 7-8:

```
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]
```

## Impact:

Disabling CSRF protections is security-sensitive.
Normally, ASP.NET Core validates anti-forgery tokens for requests that can change data (like POST, PUT, DELETE).</br>
This protects your app from Cross-Site Request Forgery (CSRF) attacks.</br>
`[IgnoreAntiforgeryToken]` disables that protection for this page.

## Recommendation:

SonarQube proposes:</br>
`new ValidateAntiForgeryTokenAttribute()`

My opinion: No action required.</br>
It's fine to disable CSRF protection on this error page because it’s just displaying an error message and not doing anything sensitive.

# Make sure that using this pseudorandom number generator is safe here.

Using pseudorandom number generators (PRNGs) is security-sensitive.</br>
Status: To Review

## Description:

Location:

> Caltec.StudentInfoProject.Persistence/Initializer/DbInitializer.cs</br>
> Line 12:

```
private static readonly Random random = new Random();
```

PRNGs are algorithms that produce sequences of numbers that only approximate true randomness.

## Impact:

PRNGs are not appropriate for security-sensitive contexts because their outputs can be predictable if the internal state is known.

## Recommendation:

Use cryptographically secure pseudorandom number generators (CSPRNGs), which are designed to be secure against prediction attacks.

The random variable is used in the following functions:

```
private static List<Degree> CreateDegrees(int nbDegree)
private static List<Student> CreateStudents(int nbStudent)
private static List<StudentClass> CreateClassesAndFees(int nbStudentPerClass, List<Student> students, List<Degree> degrees)
```

These functions generate mockData which is of no security-sensitive importance.</br>
No action needed.

# Make sure using a dynamically formatted SQL query is safe here.

## Identification:

Vulnérabilité : Injection SQL
Formatting SQL queries is security-sensitive</br>
Niveau de gravité : Élevé

## Description:

Localisation:

> Caltec.StudentInfoProject.Business/StudentService.cs</br>
> ligne 73

```
var query = $"INSERT INTO Students (FirstName, LastName) VALUES ('{StudentToInsert.FirstName}', '{StudentToInsert.LastName}')";
StudentInfoDbContext.Database.ExecuteSqlRaw(query);
```

## Impact:

L’utilisation de requêtes SQL dynamiques sans protection adéquate peut permettre l’injection SQL, compromettant ainsi la base de données et exposant des données sensibles.

-   Compromission des données utilisateurs.
-   Exécution de requêtes malveillant par un attaquant.
-   Perte potentielle de données.

## Recommendation:

Utiliser des requêtes paramétrées et lier des variables aux paramètre de requête SQL.

```
public void Foo(DbContext context, string query, string param)
{
    context.Database.ExecuteSqlCommand("SELECT * FROM mytable WHERE mycol=@p0", param); // Compliant, it's a parametrized safe query
}
```

# Copying recursively might inadvertently add sensitive data to the container.

## Identification:

Recursively copying context directories is security-sensitive.</br>
Status: Medium

## Description:

Localisation:

> Caltec.StudentInfoProject.WebUi/Dockerfile</br>
> Line 12:

```
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Caltec.StudentInfoProject.WebUi/Caltec.StudentInfoProject.WebUi.csproj", "Caltec.StudentInfoProject.WebUi/"]
RUN dotnet restore "Caltec.StudentInfoProject.WebUi/Caltec.StudentInfoProject.WebUi.csproj"
COPY . .

```

## Impact:

Dans ce code, il y a une utilisation automatique de `copy . .` pour copier l'ensemble du docker, ce qui peut engendrer une fuite des données, car on n'a pas de maitrise sur les fichiers que l'on souhaite intégrer au projet.

## Recommendation:

On recommande de ne pas utiliser une commande global, mais plutot de choisir les fichiers que l'on souhaite integrer.

# This image might run with "root" as the default user.

Running containers as a privileged user is security-sensitive</br>
Status: Medium

## Description:

> Caltec.StudentInfoProject.WebUi/Dockerfile</br>
> Line 19:

`FROM base AS final`

## Impact:

Dans ce code, le docker tourne en `root`.</br>
L’utilisateur root a tous les droits : modifier des fichiers systèmes, installer des paquets, changer des permissions, accéder à des sockets systèmes, etc. Il peut avoir une action malveillante, mais aussi des actions non intentionnelles (ouvrir des ports sensibles, supprimer des fichiers...)

## Recommendation:

On recommande de ne pas tourner en root le docker, mais de donner des accès/droits restreints.

# Notre super DependaBot qu'on aime

[image](./Screenshot%20From%202025-04-04%2012-22-57.png)
