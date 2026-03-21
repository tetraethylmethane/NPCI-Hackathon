import { PrismaClient } from '@prisma/client'

const globalForPrisma = global as unknown as { prisma: PrismaClient }

const url = "postgresql://neondb_owner:npg_dSDOuA17TyUs@ep-dry-tooth-a1oiyi3b.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    datasources: {
      db: {
        url: url,
      },
    },
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma