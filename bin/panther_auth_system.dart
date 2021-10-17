import 'dart:io';

import 'package:args/args.dart';
import 'package:crypto/crypto.dart';
import 'package:mysql1/mysql1.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';

import 'constants.dart';

String? portEnv = Platform.environment['port'];
String host = portEnv == null ? 'localhost' : '0.0.0.0';

void main(List<String> arguments) async {
  // Configuration
  final ArgParser parser = ArgParser()..addOption('port', abbr: 'p');
  final ArgResults result = parser.parse(arguments);

  final String portStr = result['port'] ?? portEnv ?? '8080';
  final int? port = int.tryParse(portStr);
  assert(port != null);
  port!;

  final Router app = Router();

  final ConnectionSettings settings = ConnectionSettings(
    host: 'eu-cdbr-west-01.cleardb.com',
    port: 3306,
    user: 'bc484050dcc36e',
    password: '5e7a4d9f',
    db: 'heroku_fa30cd5a1aa6cfb',
  );
  final MySqlConnection conn = await MySqlConnection.connect(settings);

  // Handle Requests here
  app.get("/", (Request request) {
    return Response.ok("Welcome to Panther Authentication System");
  });

  app.get("/projects/all", (Request request) async {
    Results result = await conn.query("select * from projects");
    List<Map<String, dynamic>> projects = [];
    for (ResultRow row in result) {
      projects.add(row.fields);
    }
    return Response.ok(projects.toString());
  });

  app.get("/developers/all", (Request request) async {
    Results result = await conn.query("select * from developers");
    List<Map<String, dynamic>> developers = [];
    for (ResultRow row in result) {
      developers.add(row.fields);
    }
    return Response.ok(developers.toString());
  });

  app.get("/users/<projectID>", (Request request, String projectID) async {
    if (!alphanumeric.hasMatch(projectID)) return Response.forbidden("Id $projectID is not valid : must be alphanumeric characters only");

    Results projectResult = await conn.query("select * from projects where projectIDHash = ?", [projectID]);
    if (projectResult.isEmpty) return Response.notFound("Project with id $projectID not found");
    Map<String, dynamic> project = projectResult.toList().first.fields;

    if (checkEmpty(request.url.queryParameters["developerID"])) return Response.forbidden("Developer ID not provided");
    if (sha512256.convert(project["developerID"].toString().codeUnits).toString() != request.url.queryParameters["developerIDHash"]) return Response.forbidden("Developer ID not id of project owner");
    if (checkEmpty(request.url.queryParameters["password"])) return Response.forbidden("Password not provided");
    String passwordHash = sha512256.convert(request.url.queryParameters["password"]!.codeUnits).toString();

    Results authResult = await conn.query(
      "select * from developers where developerIDHash = ? and passwordHash = ?",
      [request.url.queryParameters["developerIDHash"], passwordHash],
    );
    if (authResult.isEmpty) return Response.forbidden("Project owner details are incorrect");

    Results result = await conn.query("select * from endusers where projectIDHash = ?", [projectID]);
    List<Map<String, dynamic>> users = [];
    for (ResultRow row in result) {
      users.add(row.fields);
    }
    return Response.ok(users.toString());
  });

  app.get("/projects/id/<id>", (Request request, String id) async {
    if (!alphanumeric.hasMatch(id)) return Response.forbidden("Id $id is not valid : must be alphanumeric characters only");

    Results result = await conn.query("select * from projects where projectIDHash = ?", [id]);
    List<Map<String, dynamic>> projects = [];
    for (ResultRow row in result) {
      projects.add(row.fields);
    }

    if (projects.isEmpty) {
      await Future.delayed(Duration(milliseconds: 500));
      Results result = await conn.query("select * from projects where projectIDHash = ?", [id]);
      List<Map<String, dynamic>> projects = [];
      for (ResultRow row in result) {
        projects.add(row.fields);
      }
      if (projects.isEmpty) {
        return Response.notFound("No projects exist with id: $id");
      } else {
        return Response.ok(projects.toString());
      }
    } else {
      return Response.ok(projects.toString());
    }
  });

  app.put("/projects/new", (Request request) async {
    if (checkEmpty(request.url.queryParameters["projectName"])) return Response.forbidden("Project name is required");
    if (checkEmpty(request.url.queryParameters["developerID"])) return Response.forbidden("Developer ID is required");

    Results developer = await conn.query("select * from developers where developerIDHash = ?", [request.url.queryParameters["developerID"]]);

    Results result = await conn.query(
      "insert into projects(projectName, developerID) values(?, ?)",
      [request.url.queryParameters["projectName"], developer.first.fields["id"]],
    );
    await conn.query(
      "update projects set projectIDHash = ? where projectID = ?",
      [sha512256.convert(result.insertId!.toString().codeUnits).toString(), result.insertId!],
    );
    return Response.ok("Project with id ${sha512256.convert(result.insertId!.toString().codeUnits).toString()} created");
  });

  app.put("/developers/new", (Request request) async {
    if (checkEmpty(request.url.queryParameters["developerName"])) return Response.forbidden("Developer name required");
    if ((request.url.queryParameters["developerName"] as String).length > 25) return Response.forbidden("Developer name must be a maximum of 25 characters");
    if (checkEmpty(request.url.queryParameters["email"])) return Response.forbidden("Developer email must be provided");
    if (checkEmpty(request.url.queryParameters["password"])) return Response.forbidden("Developer password must be provided");

    Results result = await conn.query(
      "insert into developers(developerName, email, passwordHash) values(?, ?, ?)",
      [request.url.queryParameters["developerName"], request.url.queryParameters["email"], sha512256.convert(request.url.queryParameters["password"].toString().codeUnits).toString],
    );
  });

  // Serve the application
  await serve(app, host, port);
}
