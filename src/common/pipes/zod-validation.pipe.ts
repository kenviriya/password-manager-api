import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  PipeTransform,
} from '@nestjs/common';
import type { ZodIssue, ZodType } from 'zod';

type ZodValidationPipeOptions = {
  errorMessage?: string;
};

type FormattedZodIssue = {
  code: string;
  path: string;
  message: string;
};

@Injectable()
export class ZodValidationPipe<TOutput = unknown> implements PipeTransform {
  constructor(
    private readonly schema: ZodType<TOutput>,
    private readonly options: ZodValidationPipeOptions = {},
  ) {}

  transform(value: unknown, metadata: ArgumentMetadata): TOutput {
    const parsed = this.schema.safeParse(value);

    if (!parsed.success) {
      throw new BadRequestException({
        message: this.options.errorMessage ?? 'Validation failed',
        code: 'VALIDATION_ERROR',
        source: metadata.type,
        field: metadata.data ?? null,
        issues: parsed.error.issues.map((issue) => this.formatIssue(issue)),
      });
    }

    return parsed.data;
  }

  private formatIssue(issue: ZodIssue): FormattedZodIssue {
    return {
      code: issue.code,
      path: issue.path.length > 0 ? issue.path.join('.') : '$',
      message: issue.message,
    };
  }
}
