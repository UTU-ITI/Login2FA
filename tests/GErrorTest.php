<?php
// tests/GErrorTest.php

use PHPUnit\Framework\TestCase;

class GErrorTest extends TestCase {
    
    // ==================== TESTS MODO INCLUSIVE ====================
    
    public function testInclusiveAcceptsValidValue() {
        $filter = new GError(
            "RoleValidator",
            GError::badRequest,
            GError::inclusive,
            ["admin", "editor", "viewer"],
            "AuthSystem"
        );
        
        $result = $filter->filter("admin");
        $this->assertEquals("admin", $result);
        $this->assertEmpty($filter->getResidue());
    }
    
    public function testInclusiveRejectsInvalidValue() {
        $filter = new GError(
            "RoleValidator",
            GError::badRequest,
            GError::inclusive,
            ["admin", "editor", "viewer"],
            "AuthSystem"
        );
        
        $result = $filter->filter("hacker");
        $this->assertNull($result);
        $this->assertContains("hacker", $filter->getResidue());
    }
    
    public function testInclusiveWithCallable() {
        $filter = new GError(
            "AgeValidator",
            GError::badRequest,
            GError::inclusive,
            [
                "adult" => fn($age) => $age >= 18,
                "senior" => fn($age) => $age >= 65
            ],
            "AgeCheck"
        );
        
        $this->assertEquals(25, $filter->filter(25));
        $this->assertNull($filter->filter(15));
    }
    
    // ==================== TESTS MODO EXCLUSIVE ====================
    
    public function testExclusiveRejectsBlockedValue() {
        $filter = new GError(
            "ContentFilter",
            GError::forbidden,
            GError::exclusive,
            ["spam", "malware", "phishing"],
            "SecurityLayer"
        );
        
        $result = $filter->filter("spam");
        $this->assertNull($result);
        $this->assertContains("spam", $filter->getResidue());
    }
    
    public function testExclusiveAcceptsCleanValue() {
        $filter = new GError(
            "ContentFilter",
            GError::forbidden,
            GError::exclusive,
            ["spam", "malware", "phishing"],
            "SecurityLayer"
        );
        
        $result = $filter->filter("legitimate content");
        $this->assertEquals("legitimate content", $result);
    }
    
    public function testExclusiveWithCallable() {
        $filter = new GError(
            "BlacklistFilter",
            GError::forbidden,
            GError::exclusive,
            [
                "contains_script" => fn($c) => str_contains($c, "<script"),
                "contains_sql" => fn($c) => preg_match('/union|select/i', $c)
            ],
            "XSSFilter"
        );
        
        $this->assertNull($filter->filter("<script>alert(1)</script>"));
        $this->assertEquals("safe text", $filter->filter("safe text"));
    }
    
    // ==================== TESTS MODO ALL_MATCH ====================
    
    public function testAllMatchPassesWhenAllConditionsMet() {
        $filter = new GError(
            "PasswordStrength",
            GError::badRequest,
            GError::all_match,
            [
                "min_length" => fn($p) => strlen($p) >= 8,
                "has_uppercase" => fn($p) => preg_match('/[A-Z]/', $p),
                "has_number" => fn($p) => preg_match('/[0-9]/', $p),
                "has_special" => fn($p) => preg_match('/[^A-Za-z0-9]/', $p)
            ],
            "PasswordPolicy"
        );
        
        $result = $filter->filter("Secure@123");
        $this->assertEquals("Secure@123", $result);
        $this->assertEmpty($filter->getErrDetails());
    }
    
    public function testAllMatchFailsWhenAnyConditionFails() {
        $filter = new GError(
            "PasswordStrength",
            GError::badRequest,
            GError::all_match,
            [
                "min_length" => fn($p) => strlen($p) >= 8,
                "has_uppercase" => fn($p) => preg_match('/[A-Z]/', $p),
                "has_number" => fn($p) => preg_match('/[0-9]/', $p),
                "has_special" => fn($p) => preg_match('/[^A-Za-z0-9]/', $p)
            ],
            "PasswordPolicy"
        );
        
        $result = $filter->filter("weak");
        $this->assertNull($result);
        $this->assertNotEmpty($filter->getErrDetails());
        $this->assertContains("min_length", $filter->getErrDetails());
        $this->assertContains("has_uppercase", $filter->getErrDetails());
    }
    
    public function testAllMatchTracksAllFailedConditions() {
        $filter = new GError(
            "FormValidator",
            GError::badRequest,
            GError::all_match,
            [
                "email_valid" => fn($d) => filter_var($d['email'], FILTER_VALIDATE_EMAIL),
                "age_valid" => fn($d) => $d['age'] >= 18,
                "terms_accepted" => fn($d) => $d['terms'] === true
            ],
            "Registration"
        );
        
        $invalidData = [
            'email' => 'invalid-email',
            'age' => 15,
            'terms' => false
        ];
        
        $result = $filter->filter($invalidData);
        $this->assertNull($result);
        $this->assertCount(3, $filter->getErrDetails());
    }
    
    // ==================== TESTS MODO STRICT_EXCLUDE ====================
    
    public function testStrictExcludeRejectsWhenAllConditionsTrue() {
        $filter = new GError(
            "DangerDetector",
            GError::forbidden,
            GError::strict_exclude,
            [
                fn($x) => str_contains($x, "danger"),
                fn($x) => strlen($x) < 10
            ],
            "SafetyCheck"
        );
        
        $result = $filter->filter("danger");
        $this->assertNull($result); // Ambas condiciones true
    }
    
    public function testStrictExcludeAcceptsWhenAnyConditionFalse() {
        $filter = new GError(
            "DangerDetector",
            GError::forbidden,
            GError::strict_exclude,
            [
                fn($x) => str_contains($x, "danger"),
                fn($x) => strlen($x) < 10
            ],
            "SafetyCheck"
        );
        
        $result = $filter->filter("danger is a long string");
        $this->assertEquals("danger is a long string", $result); // Segunda condición false
    }
    
    // ==================== TESTS AUTO-THROW ====================
    
    public function testAutoThrowThrowsExceptionOnFailure() {
        $filter = new GError(
            "StrictAuth",
            GError::forbidden,
            GError::exclusive,
            ["blocked_user"],
            "API",
            true, // autoThrow activado
            "Acceso denegado"
        );
        
        $this->expectException(Exception::class);
        $filter->filter("blocked_user");
    }
    
    public function testAutoThrowExceptionContainsProperData() {
        $filter = new GError(
            "StrictAuth",
            GError::forbidden,
            GError::exclusive,
            ["blocked"],
            "API",
            true,
            "Acceso denegado"
        );
        
        try {
            $filter->filter("blocked");
            $this->fail("Should have thrown exception");
        } catch (Exception $e) {
            $error = json_decode($e->getMessage(), true);
            $this->assertEquals(403, $error['status']);
            $this->assertEquals("Acceso denegado", $error['message']);
            $this->assertEquals("StrictAuth", $error['name']);
            $this->assertContains("blocked", $error['residue']);
        }
    }
    
    // ==================== TESTS CALLABLES ====================
    
    public function testStaticMethodCallable() {
        $filter = new GError(
            "EmailValidator",
            GError::badRequest,
            GError::inclusive,
            [
                "email" => ['ValidatorHelpers', 'isEmail']
            ],
            "FormValidation"
        );
        
        // Asumir que ValidatorHelpers::isEmail existe
        $this->assertNotNull($filter->filter("test@example.com"));
    }
    
    public function testLambdaCallable() {
        $customValidator = fn($x) => is_int($x) && $x > 0;
        
        $filter = new GError(
            "PositiveInt",
            GError::badRequest,
            GError::inclusive,
            [
                "positive" => $customValidator
            ],
            "MathValidator"
        );
        
        $this->assertEquals(5, $filter->filter(5));
        $this->assertNull($filter->filter(-5));
    }
    
    // ==================== TESTS RESIDUE Y ERROR DETAILS ====================
    
    public function testResidueAccumulatesRejectedValues() {
        $filter = new GError(
            "TestFilter",
            GError::badRequest,
            GError::inclusive,
            ["valid"],
            "Test"
        );
        
        $filter->filter("invalid1");
        $filter->filter("invalid2");
        $filter->filter("valid");
        $filter->filter("invalid3");
        
        $residue = $filter->getResidue();
        $this->assertCount(3, $residue);
        $this->assertContains("invalid1", $residue);
        $this->assertContains("invalid2", $residue);
        $this->assertContains("invalid3", $residue);
    }
    
    public function testErrDetailsOnlyIncludesNonIntegerKeys() {
        $filter = new GError(
            "MixedKeys",
            GError::badRequest,
            GError::all_match,
            [
                "named_check" => fn($x) => false,
                fn($x) => false, // índice 0
                "another_named" => fn($x) => false
            ],
            "Test"
        );
        
        $filter->filter("test");
        $details = $filter->getErrDetails();
        
        $this->assertContains("named_check", $details);
        $this->assertContains("another_named", $details);
        $this->assertNotContains(0, $details);
    }
    
    // ==================== TESTS SETTERS Y GETTERS ====================
    
    public function testSettersModifyProperties() {
        $filter = new GError(
            "TestFilter",
            GError::badRequest,
            GError::inclusive,
            ["test"],
            "Origin"
        );
        
        $filter->setName("NewName");
        $filter->setErrorType(GError::forbidden);
        $filter->setOrigin("NewOrigin");
        $filter->setAutoThrow(true);
        $filter->setErrMessage("New Message");
        
        $this->assertEquals("NewName", $filter->getName());
        $this->assertEquals(403, $filter->getErrorType());
        $this->assertEquals("NewOrigin", $filter->getOrigin());
        $this->assertTrue($filter->getAutoThrow());
        $this->assertEquals("New Message", $filter->getErrMessage());
    }
    
    public function testClearErrorsResetsResidue() {
        $filter = new GError(
            "TestFilter",
            GError::badRequest,
            GError::inclusive,
            ["valid"],
            "Test"
        );
        
        $filter->filter("invalid1");
        $filter->filter("invalid2");
        $this->assertTrue($filter->hasErrors());
        
        $filter->clearErrors();
        $this->assertFalse($filter->hasErrors());
        $this->assertEmpty($filter->getResidue());
    }
    
    // ==================== TESTS CASOS EDGE ====================
    
    public function testEmptySamplesArray() {
        $filter = new GError(
            "EmptyFilter",
            GError::badRequest,
            GError::inclusive,
            [],
            "Test"
        );
        
        $result = $filter->filter("anything");
        $this->assertNull($result); // Ningún sample coincide
    }
    
    public function testNullInputHandling() {
        $filter = new GError(
            "NullTest",
            GError::badRequest,
            GError::inclusive,
            [null],
            "Test"
        );
        
        $result = $filter->filter(null);
        $this->assertNull($result); // null === null es true
    }
    
    public function testComplexDataStructure() {
        $filter = new GError(
            "UserValidator",
            GError::badRequest,
            GError::all_match,
            [
                "has_email" => fn($u) => isset($u['email']),
                "has_name" => fn($u) => isset($u['name']) && !empty($u['name']),
                "age_valid" => fn($u) => isset($u['age']) && $u['age'] >= 18
            ],
            "Registration"
        );
        
        $validUser = [
            'email' => 'user@example.com',
            'name' => 'John Doe',
            'age' => 25
        ];
        
        $result = $filter->filter($validUser);
        $this->assertEquals($validUser, $result);
    }
    
    // ==================== TESTS DE INTEGRACIÓN ====================
    
    public function testChainedValidation() {
        // Primer filtro: lista blanca de roles
        $roleFilter = new GError(
            "RoleCheck",
            GError::forbidden,
            GError::inclusive,
            ["admin", "editor"],
            "Auth"
        );
        
        // Segundo filtro: verificar permisos específicos
        $permissionFilter = new GError(
            "PermissionCheck",
            GError::forbidden,
            GError::all_match,
            [
                "can_write" => fn($role) => in_array($role, ["admin", "editor"]),
                "can_delete" => fn($role) => $role === "admin"
            ],
            "Permissions"
        );
        
        $role = "admin";
        
        // Primera validación
        $validRole = $roleFilter->filter($role);
        $this->assertNotNull($validRole);
        
        // Segunda validación
        $validPermission = $permissionFilter->filter($validRole);
        $this->assertNotNull($validPermission);
    }
    
    public function testGetStatusReturnsCorrectInfo() {
        $filter = new GError(
            "StatusTest",
            GError::badRequest,
            GError::inclusive,
            ["valid"],
            "Test"
        );
        
        $filter->filter("invalid");
        $status = $filter->getStatus();
        
        $this->assertEquals("StatusTest", $status['name']);
        $this->assertEquals("i", $status['filter_type']);
        $this->assertTrue($status['has_errors']);
        $this->assertEquals(1, $status['error_count']);
    }
}

// Helper class para tests
class ValidatorHelpers {
    public static function isEmail($value): bool {
        return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    public static function isUrl($value): bool {
        return filter_var($value, FILTER_VALIDATE_URL) !== false;
    }
    
    public static function isInt($value): bool {
        return filter_var($value, FILTER_VALIDATE_INT) !== false;
    }
}