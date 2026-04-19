/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static net.bytebuddy.matcher.ElementMatchers.nameContains;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.CallableInst;
import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.RunnableInst;
import java.lang.instrument.Instrumentation;
import java.util.concurrent.*;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.utility.JavaModule;
import org.junit.jupiter.api.Test;

/**
 * Verifies that dynamic agent attachment does not break lambda classes.
 *
 * <p>On Java 8-14, lambda classes are VM anonymous classes. When ByteBuddy retransforms them during
 * dynamic attachment (agentmain), it corrupts them because they don't have class file bytes
 * accessible through a ClassLoader. This causes NoClassDefFoundError at runtime.
 *
 * <p>On Java 15+, lambdas are hidden classes that the JVM itself protects from retransformation, so
 * the test passes regardless. The $$Lambda exclusion is still needed for Java 8-14 support.
 */
class LambdaExclusionTest {

  /**
   * Replicates the agent's dynamic attachment flow (agentmain) and verifies that lambda classes
   * still work afterward.
   *
   * <p>Without the $$Lambda exclusion, this test throws NoClassDefFoundError on Java 8 because
   * retransforming VM anonymous lambda classes corrupts them.
   */
  @Test
  void lambdasWorkAfterAgentAttachment() throws Exception {
    // Phase 1: Create and exercise lambdas before agent attachment
    Callable<String> callable = () -> "before";
    assertEquals("before", callable.call());

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<String> f = executor.submit(() -> "baseline");
      assertEquals("baseline", f.get());
    } finally {
      executor.shutdown();
      executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    // Phase 2: Install the agent's ByteBuddy transformer
    // This replicates Agent.builder() — same LocationStrategy, ignore rules, and
    // RETRANSFORMATION strategy that triggers retransformation of already-loaded classes.
    Instrumentation inst = ByteBuddyAgent.install();

    java.lang.instrument.ClassFileTransformer transformer =
        new AgentBuilder.Default()
            .with(
                new AgentBuilder.LocationStrategy() {
                  @Override
                  public ClassFileLocator classFileLocator(
                      ClassLoader classLoader, JavaModule module) {
                    return ClassFileLocator.ForClassLoader.of(classLoader);
                  }
                })
            .disableClassFormatChanges()
            .ignore(nameStartsWith("io.opentelemetry.obi"))
            .ignore(nameContains("$$Lambda"))
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
            .type(RunnableInst.type())
            .transform(RunnableInst.transformer())
            .type(CallableInst.type())
            .transform(CallableInst.transformer())
            .type(JavaExecutorInst.type())
            .transform(JavaExecutorInst.transformer())
            .installOn(inst);

    try {
      // Phase 3: Replicate the agentmain retransformation loop
      // This iterates all loaded classes and retransforms matching ones,
      // exactly as Agent.agentmain() does after calling premain().
      for (Class<?> clazz : inst.getAllLoadedClasses()) {
        if (clazz.getName().contains("$$Lambda")) {
          continue;
        }
        if (JavaExecutorInst.matches(clazz)
            || CallableInst.matches(clazz)
            || RunnableInst.matches(clazz)) {
          try {
            inst.retransformClasses(clazz);
          } catch (Throwable t) {
            // Some classes can't be retransformed — that's expected
          }
        }
      }

      // Phase 4: Exercise lambdas after agent attachment
      // Without the $$Lambda exclusion on Java 8, this throws:
      //   java.lang.NoClassDefFoundError: LambdaExclusionTest$$Lambda$XX
      executor = Executors.newSingleThreadExecutor();
      try {
        Future<String> f = executor.submit(() -> "after-attach");
        assertEquals("after-attach", f.get());

        executor.submit((Runnable) () -> {}).get();
      } finally {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
      }
    } finally {
      inst.removeTransformer(transformer);
    }
  }
}
