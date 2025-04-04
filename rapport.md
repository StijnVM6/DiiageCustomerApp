# Make sure this database password gets changed and removed from the code.

## Identification:

Software qualities impacted: Security - Blocker

## Description:

Location:

> Caltec.StudentInfoProject.Persistence/StudentInfoDbContextFactory.cs
> Line 15:

```
//string connexionString = "tcp:trainingmanagementsqlserver.Database.windows.net:1433;Initial Catalog=TrainingManagement;Persist Security Info=False;User ID=trainingadmin;Password=DevDb2019!;MultipleActiveResultsSets=False;Encrypt=True;ConnectionTimeout=30;";
```

## Impact:

Database passwords should not be disclosed:
`Password=DevDb2019!;`

## Recommendation:

Remove secret !
Use system environmnet variables to access secrets.
`System.getenv("DB_PASSWORD")`

# Make sure disabling CSRF protection is safe here.

## Identification:

Cross-site request forgery CSRF.
Status: To Review

## Description:

Location:

> Caltec.StudentInfoProject.WebUi/Pages/Error.cshtml.cs
> Line 7-8:

```
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [IgnoreAntiforgeryToken]
```

## Impact:

Disabling CSRF protections is security-sensitive.
Normally, ASP.NET Core validates anti-forgery tokens for requests that can change data (like POST, PUT, DELETE).
This protects your app from Cross-Site Request Forgery (CSRF) attacks.
`[IgnoreAntiforgeryToken]` disables that protection for this page.

## Recommendation:

SonarQube proposes:
`new ValidateAntiForgeryTokenAttribute()`

My opinion: No action required.
It's fine to disable CSRF protection on this error page because it’s just displaying an error message and not doing anything sensitive.

# Make sure that using this pseudorandom number generator is safe here.

Using pseudorandom number generators (PRNGs) is security-sensitive.
Status: To Review

## Description:

Location:

> Caltec.StudentInfoProject.Persistence/Initializer/DbInitializer.cs
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

These functions generate mockData which is of no security-sensitive importance.
No action needed.

# Make sure using a dynamically formatted SQL query is safe here.

## Identification:

Vulnérabilité : Injection SQL
Formatting SQL queries is security-sensitive
Niveau de gravité : Élevé

## Description:

Localisation:

> Caltec.StudentInfoProject.Business/StudentService.cs
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
