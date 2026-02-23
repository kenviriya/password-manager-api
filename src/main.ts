import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { ApiExceptionFilter } from './common/filters/api-exception.filter';
import { ApiResponseInterceptor } from './common/interceptors/api-response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: ['http://localhost:3000', 'https://app.kenviriya.space'],
    credentials: true,
  });
  app.enableShutdownHooks();
  app.useGlobalFilters(new ApiExceptionFilter());
  app.useGlobalInterceptors(new ApiResponseInterceptor());

  const swaggerConfig = new DocumentBuilder()
    .setTitle('Password Manager API')
    .setDescription('API documentation for the Password Manager backend')
    .setVersion('1.0.0')
    .addCookieAuth('sid', {
      type: 'apiKey',
      in: 'cookie',
      name: 'sid',
    })
    .build();

  const swaggerDocument = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, swaggerDocument, {
    jsonDocumentUrl: 'docs-json',
  });

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
